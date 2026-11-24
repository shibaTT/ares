import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';

import '../models/connection.dart';
import '../models/ssh_tunnel.dart';

/// Raised when an SSH-backed connection cannot be established.
class SshTunnelException implements Exception {
  final String message;
  const SshTunnelException(this.message);

  @override
  String toString() => message;
}

/// The gateway endpoint discovered on the SSH host.
class SshAttachEndpoint {
  /// Base HTTP origin of the gateway (for example `http://127.0.0.1:47595`).
  final Uri origin;

  /// WebSocket URL of the gateway's `/api/ws` socket, when reported.
  final String? wsUrl;

  /// Single-use attach ticket, when reported.
  final String? ticket;

  /// WebSocket sub-protocols the ticket must be dialled with.
  final List<String> protocols;

  /// `SHA256:...` fingerprint of the SSH host key the server presented.
  final String? hostKeyFingerprint;

  const SshAttachEndpoint({
    required this.origin,
    required this.protocols,
    this.wsUrl,
    this.ticket,
    this.hostKeyFingerprint,
  });

  /// Port on the SSH host's loopback interface that serves the gateway.
  int get remotePort => origin.hasPort
      ? origin.port
      : (origin.scheme == 'https' || origin.scheme == 'wss' ? 443 : 80);
}

/// A live SSH tunnel for one saved connection.
class SshTunnelSession {
  /// Connection this tunnel belongs to.
  final String connectionId;

  /// SSH settings used to dial.
  final SshTunnelConfig config;

  /// Local loopback origin the app should dial, e.g. `http://127.0.0.1:41237`.
  final String baseUrl;

  /// Local port bound by the tunnel.
  final int localPort;

  /// Gateway origin on the SSH host.
  final Uri remoteOrigin;

  /// Attach ticket and socket URLs reported by the gateway.
  final String? ticket;
  final String? wsUrl;
  final List<String> protocols;

  /// Host key fingerprint observed during the handshake.
  final String? hostKeyFingerprint;

  /// When the tunnel came up.
  final DateTime startedAt;

  SshTunnelSession({
    required this.connectionId,
    required this.config,
    required this.baseUrl,
    required this.localPort,
    required this.remoteOrigin,
    required this.protocols,
    this.ticket,
    this.wsUrl,
    this.hostKeyFingerprint,
  }) : startedAt = DateTime.now();

  Uri get uri => Uri.parse(baseUrl);

  /// Same tunnel, with a freshly minted attach credential.
  SshTunnelSession copyWithAttach({
    String? ticket,
    String? wsUrl,
    List<String>? protocols,
  }) => SshTunnelSession(
    connectionId: connectionId,
    config: config,
    baseUrl: baseUrl,
    localPort: localPort,
    remoteOrigin: remoteOrigin,
    protocols: protocols ?? this.protocols,
    ticket: ticket ?? this.ticket,
    wsUrl: wsUrl ?? this.wsUrl,
    hostKeyFingerprint: hostKeyFingerprint,
  );
}

/// Starts and owns SSH tunnels for Hermes connections.
///
/// A tunnel dials the SSH host, runs `hermes gateway attach` there and forwards
/// a loopback port on this device to the gateway's loopback port. The gateway
/// that already serves the user's messaging platforms is reused: no extra
/// server process is started, and nothing but the SSH port has to be reachable.
class SshTunnelService {
  SshTunnelService._();

  static final SshTunnelService instance = SshTunnelService._();

  static const Duration connectTimeout = Duration(seconds: 25);
  static const Duration attachTimeout = Duration(seconds: 40);

  final Map<String, _Tunnel> _tunnels = <String, _Tunnel>{};

  /// Base URL currently tunnelled for [connectionId], if any.
  String? baseUrlFor(String connectionId) => _tunnels[connectionId]?.session.baseUrl;

  /// Session currently tunnelled for [connectionId], if any.
  SshTunnelSession? sessionFor(String connectionId) => _tunnels[connectionId]?.session;

  /// Whether a live tunnel exists for [connectionId].
  bool hasTunnel(String connectionId) => _tunnels.containsKey(connectionId);

  /// Ensures [connection] is reachable through an SSH tunnel and returns its
  /// session. Reuses a live tunnel, and restarts one whose SSH client died.
  Future<SshTunnelSession> ensure({
    required SavedConnection connection,
    required String privateKeyPem,
  }) async {
    final config = connection.ssh;
    if (config == null) {
      throw const SshTunnelException('This connection has no SSH tunnel settings.');
    }
    if (!config.isComplete) {
      throw const SshTunnelException('SSH host, user and port must all be set.');
    }

    final existing = _tunnels[connection.id];
    if (existing != null && !existing.isClosed) {
      return existing.session;
    }
    if (existing != null) {
      await close(connection.id);
    }

    final key = privateKeyPem.trim();
    if (key.isEmpty) {
      throw const SshTunnelException(
        'No SSH private key stored for this connection. Add the key in the connection settings.',
      );
    }

    final List<SSHKeyPair> identities;
    try {
      identities = SSHKeyPair.fromPem(key);
    } catch (error) {
      throw SshTunnelException(
        'The SSH private key could not be parsed. Paste an OpenSSH or PEM key (no passphrase).',
      );
    }

    String? observedFingerprint;
    final pin = _normalizeFingerprint(config.hostKeySha256);

    final SSHSocket socket;
    try {
      socket = await SSHSocket.connect(
        config.host,
        config.port,
        timeout: connectTimeout,
      );
    } catch (error) {
      throw SshTunnelException(
        'Could not reach ${config.host}:${config.port} over SSH: $error',
      );
    }

    final client = SSHClient(
      socket,
      username: config.username,
      identities: identities,
      onVerifyHostKey: (String type, Uint8List fingerprintBytes) {
        observedFingerprint = _formatFingerprint(fingerprintBytes);
        if (pin == null) return true;
        return _normalizeFingerprint(observedFingerprint) == pin;
      },
    );

    try {
      await client.authenticated.timeout(
        connectTimeout,
        onTimeout: () => throw const SshTunnelException(
          'SSH authentication timed out. Check the user and that the key is authorised on the host.',
        ),
      );
    } on SshTunnelException {
      await _disposeClient(client);
      rethrow;
    } catch (error) {
      await _disposeClient(client);
      throw SshTunnelException(_describeSshFailure(error, config, observedFingerprint));
    }

    final SshAttachEndpoint endpoint;
    try {
      endpoint = await _attach(client, config).timeout(
        attachTimeout,
        onTimeout: () => throw const SshTunnelException(
          'The gateway attach command did not answer in time.',
        ),
      );
    } catch (error) {
      await _disposeClient(client);
      if (error is SshTunnelException) rethrow;
      throw SshTunnelException('Gateway attach failed: $error');
    }

    final ServerSocket server;
    try {
      server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    } catch (error) {
      await _disposeClient(client);
      throw SshTunnelException('Could not open a local tunnel port: $error');
    }

    final tunnel = _Tunnel(
      session: SshTunnelSession(
        connectionId: connection.id,
        config: config,
        baseUrl: 'http://127.0.0.1:${server.port}',
        localPort: server.port,
        remoteOrigin: endpoint.origin,
        protocols: endpoint.protocols,
        ticket: endpoint.ticket,
        wsUrl: endpoint.wsUrl,
        hostKeyFingerprint: endpoint.hostKeyFingerprint ?? observedFingerprint,
      ),
      client: client,
      server: server,
    );
    _tunnels[connection.id] = tunnel;
    tunnel.listen();
    return tunnel.session;
  }

  /// Mints a fresh attach credential over a live tunnel.
  ///
  /// `hermes gateway attach` tickets are single-use and expire within seconds,
  /// so every WebSocket attempt needs its own. The dashboard's HTTP ticket
  /// endpoint is not usable here: an SSH-only connection has no signed-in
  /// session to mint one with.
  Future<SshTunnelSession> refreshAttach(String connectionId) async {
    final tunnel = _tunnels[connectionId];
    if (tunnel == null || tunnel.isClosed) {
      throw const SshTunnelException(
        'The SSH tunnel is not up. Reconnect to bring it back.',
      );
    }
    final endpoint = await _attach(tunnel.client, tunnel.session.config).timeout(
      attachTimeout,
      onTimeout: () => throw const SshTunnelException(
        'The gateway attach command did not answer in time.',
      ),
    );
    tunnel.session = tunnel.session.copyWithAttach(
      ticket: endpoint.ticket,
      wsUrl: endpoint.wsUrl,
      protocols: endpoint.protocols,
    );
    return tunnel.session;
  }

  /// Closes the tunnel for [connectionId], if any.
  Future<void> close(String connectionId) async {
    final tunnel = _tunnels.remove(connectionId);
    if (tunnel != null) {
      await tunnel.close();
    }
  }

  /// Closes every tunnel (app shutdown / sign-out).
  Future<void> closeAll() async {
    final tunnels = List<_Tunnel>.of(_tunnels.values);
    _tunnels.clear();
    for (final tunnel in tunnels) {
      await tunnel.close();
    }
  }

  Future<SshAttachEndpoint> _attach(
    SSHClient client,
    SshTunnelConfig config,
  ) async {
    final SSHRunResult result;
    try {
      result = await client.runWithResult(config.attachCommand);
    } catch (error) {
      throw SshTunnelException('Could not run "${config.attachCommand}": $error');
    }

    final stdoutText = utf8.decode(result.stdout, allowMalformed: true).trim();
    final stderrText = utf8.decode(result.stderr, allowMalformed: true).trim();
    final map = _lastJsonObject(stdoutText);
    if (map == null) {
      final detail = stderrText.isNotEmpty ? stderrText : stdoutText;
      throw SshTunnelException(
        'The attach command did not return JSON. ${_shorten(detail)}',
      );
    }

    final state = (map['state'] as String?)?.trim();
    if (state != null && state != 'ready') {
      final message = (map['message'] as String?)?.trim();
      final reason = (map['reason_code'] as String?)?.trim();
      throw SshTunnelException(
        'The gateway is not attachable on the host: ${message ?? reason ?? state}',
      );
    }

    final endpointMap = map['endpoint'];
    final apiOrigin = endpointMap is Map
        ? (endpointMap['api_origin'] as String?)?.trim()
        : null;
    final wsUrl = (map['url'] as String?)?.trim();
    final candidate = (apiOrigin != null && apiOrigin.isNotEmpty)
        ? apiOrigin
        : wsUrl;
    if (candidate == null || candidate.isEmpty) {
      throw const SshTunnelException(
        'The attach reply had no gateway origin. Update Hermes on the host if this persists.',
      );
    }

    final Uri parsed;
    try {
      parsed = Uri.parse(candidate);
    } catch (error) {
      throw SshTunnelException('Unreadable gateway origin "$candidate".');
    }

    final protocols = <String>[];
    final rawProtocols = map['protocols'];
    if (rawProtocols is List) {
      for (final entry in rawProtocols) {
        final text = entry?.toString().trim();
        if (text != null && text.isNotEmpty) protocols.add(text);
      }
    }

    return SshAttachEndpoint(
      origin: parsed,
      wsUrl: wsUrl,
      ticket: (map['ticket'] as String?)?.trim(),
      protocols: protocols,
    );
  }

  static Map<String, dynamic>? _lastJsonObject(String text) {
    if (text.isEmpty) return null;
    final lines = text.split(RegExp(r'\r?\n'));
    for (final line in lines.reversed) {
      final candidate = line.trim();
      if (!candidate.startsWith('{') || !candidate.endsWith('}')) continue;
      try {
        final decoded = jsonDecode(candidate);
        if (decoded is Map<String, dynamic>) return decoded;
        if (decoded is Map) return Map<String, dynamic>.from(decoded);
      } catch (_) {
        continue;
      }
    }
    return null;
  }

  static String _shorten(String text, [int limit = 200]) {
    final collapsed = text.replaceAll(RegExp(r'\s+'), ' ').trim();
    if (collapsed.length <= limit) return collapsed;
    return '${collapsed.substring(0, limit)}…';
  }

  static String? _normalizeFingerprint(String? value) {
    final text = value?.trim();
    if (text == null || text.isEmpty) return null;
    final withoutPrefix = text.toUpperCase().startsWith('SHA256:')
        ? text.substring('SHA256:'.length)
        : text;
    return withoutPrefix.replaceAll('=', '').trim();
  }

  static String _formatFingerprint(Uint8List bytes) {
    final encoded = base64Encode(bytes).replaceAll('=', '');
    return 'SHA256:$encoded';
  }

  static String _describeSshFailure(
    Object error,
    SshTunnelConfig config,
    String? fingerprint,
  ) {
    final text = error.toString();
    if (text.contains('Hostkey') || text.contains('hostkey')) {
      final seen = fingerprint == null ? '' : ' (host key $fingerprint)';
      return 'SSH host key verification failed for ${config.label}$seen. '
          'Clear the pinned fingerprint or update it to the value above.';
    }
    if (text.contains('Auth') ||
        text.contains('Permission denied') ||
        text.contains('auth')) {
      return 'SSH authentication failed for ${config.label}. '
          'Check that the public key is in ~/.ssh/authorized_keys on the host.';
    }
    return 'SSH connection to ${config.label} failed: ${_shorten(text)}';
  }

  static Future<void> _disposeClient(SSHClient client) async {
    try {
      client.close();
    } catch (_) {
      // Already gone.
    }
  }
}

class _Tunnel {
  _Tunnel({required this.session, required this.client, required this.server});

  /// Replaced whenever a fresh attach credential is minted.
  SshTunnelSession session;
  final SSHClient client;
  final ServerSocket server;
  final List<Socket> _sockets = <Socket>[];
  bool _closed = false;

  bool get isClosed => _closed || client.isClosed;

  void listen() {
    server.listen((Socket socket) {
      if (_closed) {
        socket.destroy();
        return;
      }
      _sockets.add(socket);
      socket.done.whenComplete(() {
        _sockets.remove(socket);
      });
      _pump(socket);
    });
  }

  Future<void> _pump(Socket socket) async {
    SSHForwardChannel channel;
    try {
      channel = await client.forwardLocal(
        session.remoteOrigin.host.isEmpty
            ? '127.0.0.1'
            : session.remoteOrigin.host,
        session.remoteOrigin.hasPort ? session.remoteOrigin.port : 80,
        localHost: '127.0.0.1',
        localPort: session.localPort,
      );
    } catch (_) {
      socket.destroy();
      return;
    }

    socket.listen(
      (Uint8List data) {
        try {
          channel.sink.add(data);
        } catch (_) {
          channel.sink.close();
          socket.destroy();
        }
      },
      onDone: () {
        try {
          channel.sink.close();
        } catch (_) {}
        socket.destroy();
      },
      onError: (_) {
        try {
          channel.sink.close();
        } catch (_) {}
        socket.destroy();
      },
      cancelOnError: true,
    );

    channel.stream.listen(
      socket.add,
      onDone: socket.destroy,
      onError: (_) => socket.destroy(),
      cancelOnError: true,
    );
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    for (final socket in List<Socket>.of(_sockets)) {
      try {
        socket.destroy();
      } catch (_) {}
    }
    _sockets.clear();
    try {
      await server.close();
    } catch (_) {}
    try {
      client.close();
    } catch (_) {}
  }
}
