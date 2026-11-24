// Root of the NextGen interface. Picks the gateway in use (or shows the
// connect screen when there is none), keeps its live connection running and
// hosts NextGen's own navigator so every screen sees [NgScope].
import 'dart:async';

import 'package:flutter/material.dart';

import '../core/services/connection_manager.dart';
import '../core/services/hermes_sign_in.dart';
import '../core/services/ssh_key_store.dart';
import '../core/services/ssh_tunnel_service.dart';
import 'data/nextgen_gateway.dart';
import 'nextgen_preferences.dart';
import 'theme/nextgen_theme.dart';
import 'ui/connect_screen.dart';
import 'ui/main_page.dart';
import 'ui/nextgen_scope.dart';
import 'nextgen_l10n.dart';

class NextGenHome extends StatefulWidget {
  const NextGenHome({super.key, required this.connManager});
  final ConnectionManager connManager;

  @override
  State<NextGenHome> createState() => _NextGenHomeState();
}

class _NextGenHomeState extends State<NextGenHome> {
  var _navigator = GlobalKey<NavigatorState>();
  List<SavedConnection>? _connections;
  NextGenGateway? _gateway;
  String? _loadError;

  ConnectionManager get _manager => widget.connManager;

  @override
  void initState() {
    super.initState();
    nextGenOpenRequest.addListener(_onOpenRequest);
    unawaited(_reload());
  }

  /// A notification named a chat: switch to its connection first; the main
  /// page opens the chat once that connection is showing.
  void _onOpenRequest() {
    final request = nextGenOpenRequest.value;
    final connections = _connections;
    if (request == null || connections == null) return;
    if (!connections.any((c) => c.id == request.connectionId)) {
      nextGenOpenRequest.value = null;
      return;
    }
    if (_gateway?.connection.id != request.connectionId) {
      unawaited(_switchTo(request.connectionId));
    } else {
      _navigator.currentState?.popUntil((r) => r.isFirst);
    }
  }

  @override
  void dispose() {
    nextGenOpenRequest.removeListener(_onOpenRequest);
    _gateway?.dispose();
    super.dispose();
  }

  Future<void> _reload({String? select, bool force = false}) async {
    try {
      final list = await _manager.loadConnectionsWithSecrets();
      if (!mounted) return;
      final pending = nextGenOpenRequest.value?.connectionId;
      final wanted =
          select ??
          (list.any((c) => c.id == pending) ? pending : null) ??
          _gateway?.connection.id ??
          NextGenPreferences.currentConnectionId(_manager.prefs);
      final pick =
          list.where((c) => c.id == wanted).firstOrNull ??
          list.where((c) => c.singleLogin).firstOrNull ??
          list.firstOrNull;
      setState(() {
        _connections = list;
        _loadError = null;
      });
      _use(pick, force: force);
    } catch (e) {
      if (mounted) setState(() => _loadError = '$e');
    }
  }

  void _use(SavedConnection? connection, {bool force = false}) {
    final current = _gateway;
    if (connection == null) {
      current?.dispose();
      setState(() => _gateway = null);
      unawaited(
        NextGenPreferences.setCurrentConnectionId(_manager.prefs, null),
      );
      return;
    }
    if (!force &&
        current != null &&
        current.connection.id == connection.id &&
        _sameAccess(current.connection, connection)) {
      return;
    }
    if (connection.ssh != null) {
      unawaited(_useViaTunnel(connection));
      return;
    }
    _activate(connection);
  }

  /// Brings up the SSH tunnel for [connection], then activates it.
  ///
  /// The gateway on the SSH host is reused (`hermes gateway attach`), so no
  /// server process is started there.
  Future<void> _useViaTunnel(SavedConnection connection) async {
    try {
      final key = await SshKeyStore.instance.readKey(connection.id);
      final session = await SshTunnelService.instance.ensure(
        connection: connection,
        privateKeyPem: key ?? '',
      );
      SavedConnection.setSshResolvedBaseUrl(connection.id, session.baseUrl);
      await _signInThroughTunnel(connection, session);
    } catch (error) {
      SavedConnection.setSshResolvedBaseUrl(connection.id, null);
      debugPrint('SSH tunnel failed for ${connection.label}: $error');
      if (!mounted) return;
      ScaffoldMessenger.maybeOf(context)?.showSnackBar(
        SnackBar(content: Text('SSH: $error')),
      );
      return;
    }
    if (!mounted) return;
    _activate(connection);
  }

  /// Signs the dashboard session in through the tunnel.
  ///
  /// The session cookie is stored per origin, and a tunnel binds a new loopback
  /// port every run, so it is re-established once per launch with the saved
  /// credentials. Skipped when no credentials were stored.
  Future<void> _signInThroughTunnel(
    SavedConnection connection,
    SshTunnelSession session,
  ) async {
    final username = connection.dashboardUsername?.trim() ?? '';
    final password = connection.dashboardPassword ?? '';
    if (username.isEmpty || password.isEmpty) return;
    final result = await HermesSignIn().passwordSignIn(
      GatewayUrl.parse(session.baseUrl),
      username: username,
      password: password,
    );
    if (result is! SignInOk) {
      debugPrint('SSH dashboard sign-in for ${connection.label}: $result');
    }
  }

  void _activate(SavedConnection connection) {
    final current = _gateway;
    final next = NextGenGateway(connection)..start();
    setState(() {
      _gateway = next;
      // A different gateway starts from a fresh navigator and chat.
      _navigator = GlobalKey<NavigatorState>();
    });
    current?.dispose();
    unawaited(
      NextGenPreferences.setCurrentConnectionId(_manager.prefs, connection.id),
    );
  }

  static bool _sameAccess(SavedConnection a, SavedConnection b) =>
      a.desktopGatewayUrl == b.desktopGatewayUrl &&
      a.dashboardUsername == b.dashboardUsername &&
      a.dashboardPassword == b.dashboardPassword &&
      a.gatewayProfile == b.gatewayProfile &&
      a.signInMethod == b.signInMethod &&
      a.ssh?.label == b.ssh?.label &&
      a.ssh?.hostKeySha256 == b.ssh?.hostKeySha256;

  Future<void> _switchTo(String id) async {
    final target = _connections?.where((c) => c.id == id).firstOrNull;
    if (target == null) return;
    _navigator.currentState?.popUntil((r) => r.isFirst);
    _use(target);
  }

  Future<void> _connectFlow({SavedConnection? existing}) async {
    final nav = _navigator.currentState;
    if (nav == null) return;
    await nav.push(
      MaterialPageRoute<void>(
        builder: (context) => NgConnectScreen(
          connManager: _manager,
          existing: existing,
          firstRun: false,
          onCancel: () => Navigator.of(context).pop(),
          onConnected: (saved) async {
            Navigator.of(context).popUntil((r) => r.isFirst);
            // A fresh sign-in replaces the gateway even when the id matches.
            await _reload(select: saved.id, force: true);
          },
        ),
      ),
    );
  }

  Future<void> _signOut(SavedConnection connection) async {
    final gateway = _gateway;
    if (gateway != null && gateway.connection.id == connection.id) {
      try {
        final headers = await gateway.dashboard.authHeaders();
        await HermesSignIn().signOut(
          gateway.url,
          authHeaders: headers,
          certificate: connection.clientCertificate,
        );
      } catch (_) {
        // Forgetting locally still signs this phone out.
      }
    }
    await _manager.deleteConnection(connection.id);
    _navigator.currentState?.popUntil((r) => r.isFirst);
    await _reload(force: true);
  }

  @override
  Widget build(BuildContext context) {
    final c = NgColors.of(context);
    final connections = _connections;
    if (_loadError != null) {
      return Scaffold(
        backgroundColor: c.background,
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text(
              ngL.ng_couldn_t_read_your_saved_gateways(_loadError ?? ''),
              textAlign: TextAlign.center,
            ),
          ),
        ),
      );
    }
    if (connections == null) {
      return Scaffold(
        backgroundColor: c.background,
        body: const Center(child: CircularProgressIndicator()),
      );
    }
    final gateway = _gateway;
    if (gateway == null) {
      return NgConnectScreen(
        connManager: _manager,
        firstRun: true,
        onConnected: (saved) => _reload(select: saved.id),
        onUseClassic: () =>
            NextGenPreferences.setEnabled(_manager.prefs, false),
      );
    }
    return NgScope(
      connManager: _manager,
      gateway: gateway,
      connections: connections,
      switchTo: _switchTo,
      addGateway: () => _connectFlow(),
      signOut: _signOut,
      reload: _reload,
      signInAgain: () => _connectFlow(existing: gateway.connection),
      child: NavigatorPopHandler(
        onPopWithResult: (_) => _navigator.currentState?.maybePop(),
        child: Navigator(
          key: _navigator,
          onGenerateInitialRoutes: (_, _) => [
            MaterialPageRoute<void>(builder: (_) => const NgMainPage()),
          ],
        ),
      ),
    );
  }
}
