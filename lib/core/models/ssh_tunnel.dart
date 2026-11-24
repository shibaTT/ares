/// SSH tunnel configuration for a Hermes connection.
///
/// When a [SavedConnection] carries one of these, the app dials the Hermes
/// gateway through an SSH tunnel instead of reaching it over the network:
///
/// 1. authenticate to the SSH host
/// 2. run `hermes gateway attach --timeout <n>` on that host
/// 3. read the WebSocket / API origin it prints
/// 4. forward a loopback port on the phone to that remote loopback origin
///
/// The gateway that already serves the user's messaging platforms is reused, so
/// no extra server process is started on the host.
class SshTunnelConfig {
  /// SSH host name or address (LAN address, Tailscale address, jump-free only).
  final String host;

  /// SSH port (default 22).
  final int port;

  /// Login user on the SSH host.
  final String username;

  /// Optional pinned host key fingerprint as `SHA256:...` or bare base64.
  /// When set, a mismatching key fails the connection. When null the host key
  /// is accepted on trust-on-first-use and the fingerprint is reported back.
  final String? hostKeySha256;

  /// Command used to discover the gateway endpoint. Must print one JSON object
  /// with an `endpoint.api_origin` / `url` field (what `hermes gateway attach`
  /// emits).
  final String attachCommand;

  const SshTunnelConfig({
    required this.host,
    required this.username,
    this.port = 22,
    this.hostKeySha256,
    this.attachCommand = defaultAttachCommand,
  });

  static const String defaultAttachCommand = 'hermes gateway attach --timeout 15';

  Map<String, dynamic> toJson() => <String, dynamic>{
    'host': host,
    'port': port,
    'username': username,
    if (hostKeySha256 != null && hostKeySha256!.trim().isNotEmpty)
      'host_key_sha256': hostKeySha256!.trim(),
    if (attachCommand.trim().isNotEmpty && attachCommand != defaultAttachCommand)
      'attach_command': attachCommand.trim(),
  };

  factory SshTunnelConfig.fromJson(Map<String, dynamic> json) {
    String? nonEmpty(Object? value) {
      final text = (value as String?)?.trim();
      return text == null || text.isEmpty ? null : text;
    }

    final command = nonEmpty(json['attach_command']);
    return SshTunnelConfig(
      host: (json['host'] as String?)?.trim() ?? '',
      port: (json['port'] as int?) ?? 22,
      username: (json['username'] as String?)?.trim() ?? '',
      hostKeySha256: nonEmpty(json['host_key_sha256']),
      attachCommand: command ?? defaultAttachCommand,
    );
  }

  SshTunnelConfig copyWith({
    String? host,
    int? port,
    String? username,
    String? hostKeySha256,
    String? attachCommand,
    bool clearHostKey = false,
  }) => SshTunnelConfig(
    host: host ?? this.host,
    port: port ?? this.port,
    username: username ?? this.username,
    hostKeySha256: clearHostKey ? null : (hostKeySha256 ?? this.hostKeySha256),
    attachCommand: attachCommand ?? this.attachCommand,
  );

  /// Human readable `user@host:port` used by the settings UI.
  String get label => '$username@$host:$port';

  /// Whether the fields needed to dial are present.
  bool get isComplete =>
      host.trim().isNotEmpty && username.trim().isNotEmpty && port > 0;

  @override
  String toString() => 'SshTunnelConfig($label)';
}
