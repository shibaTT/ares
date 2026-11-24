import 'package:flutter/material.dart';

import '../../core/models/ssh_tunnel.dart';
import '../../core/services/connection_manager.dart';
import '../../core/services/hermes_sign_in.dart';
import '../../core/services/ssh_key_store.dart';
import '../../core/services/ssh_tunnel_service.dart';

/// Placeholder dashboard address for a connection that is only ever reached
/// through its SSH tunnel. [SavedConnection.singleLoginUrl] is overridden by the
/// live tunnel address, so this value is never dialled.
const String sshOnlyPlaceholderUrl = 'http://127.0.0.1:9119';

/// Opens the SSH tunnel editor.
///
/// With a [connection] the dialog edits that connection's tunnel; without one it
/// creates a new single-login gateway that is reachable only over SSH.
/// Returns the saved connection (or null when nothing was saved).
Future<SavedConnection?> showSshTunnelDialog(
  BuildContext context, {
  SavedConnection? connection,
  required ConnectionManager connManager,
}) async {
  return showDialog<SavedConnection>(
    context: context,
    builder: (_) =>
        _SshTunnelDialog(connection: connection, connManager: connManager),
  );
}

class _SshTunnelDialog extends StatefulWidget {
  const _SshTunnelDialog({this.connection, required this.connManager});

  final SavedConnection? connection;
  final ConnectionManager connManager;

  @override
  State<_SshTunnelDialog> createState() => _SshTunnelDialogState();
}

class _SshTunnelDialogState extends State<_SshTunnelDialog> {
  late final TextEditingController _name;
  late final TextEditingController _host;
  late final TextEditingController _port;
  late final TextEditingController _user;
  late final TextEditingController _fingerprint;
  late final TextEditingController _key;

  late bool _enabled;
  bool _hasStoredKey = false;
  bool _busy = false;
  String? _error;

  bool get _isNew => widget.connection == null;

  @override
  void initState() {
    super.initState();
    final ssh = widget.connection?.ssh;
    _enabled = _isNew || ssh != null;
    _name = TextEditingController(text: widget.connection?.label ?? '');
    _host = TextEditingController(text: ssh?.host ?? '');
    _port = TextEditingController(text: '${ssh?.port ?? 22}');
    _user = TextEditingController(text: ssh?.username ?? '');
    _fingerprint = TextEditingController(text: ssh?.hostKeySha256 ?? '');
    _key = TextEditingController();
    if (!_isNew) _loadStoredKey();
  }

  Future<void> _loadStoredKey() async {
    final connection = widget.connection;
    if (connection == null) return;
    final has = await SshKeyStore.instance.hasKey(connection.id);
    if (!mounted) return;
    setState(() => _hasStoredKey = has);
  }

  @override
  void dispose() {
    _name.dispose();
    _host.dispose();
    _port.dispose();
    _user.dispose();
    _fingerprint.dispose();
    _key.dispose();
    super.dispose();
  }

  void _fail(String message) {
    setState(() {
      _error = message;
      _busy = false;
    });
  }

  Future<void> _save() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final existing = widget.connection;

    try {
      if (!_enabled && existing != null) {
        await widget.connManager.updateSshTunnel(existing.id, null);
        await SshKeyStore.instance.deleteKey(existing.id);
        await SshTunnelService.instance.close(existing.id);
        SavedConnection.setSshResolvedBaseUrl(existing.id, null);
        if (mounted) {
          Navigator.of(context).pop(existing.copyWith(clearSsh: true));
        }
        return;
      }

      final name = _name.text.trim();
      final host = _host.text.trim();
      final user = _user.text.trim();
      final port = int.tryParse(_port.text.trim()) ?? 0;
      if (_isNew && name.isEmpty) {
        _fail('Give the gateway a name.');
        return;
      }
      if (host.isEmpty || user.isEmpty || port <= 0) {
        _fail('SSH host, user and port are required.');
        return;
      }

      final pastedKey = _key.text.trim();
      if (pastedKey.isEmpty && !_hasStoredKey) {
        _fail('Paste the SSH private key (OpenSSH or PEM, no passphrase).');
        return;
      }

      final fingerprint = _fingerprint.text.trim();
      final config = SshTunnelConfig(
        host: host,
        port: port,
        username: user,
        hostKeySha256: fingerprint.isEmpty ? null : fingerprint,
      );

      String connectionId;
      SavedConnection result;
      if (existing == null) {
        result = await widget.connManager.saveSingleLoginConnection(
          url: GatewayUrl.parse(sshOnlyPlaceholderUrl),
          signInMethod: 'none',
          label: name,
        );
        connectionId = result.id;
      } else {
        connectionId = existing.id;
        result = existing;
      }

      if (pastedKey.isNotEmpty) {
        await SshKeyStore.instance.writeKey(connectionId, pastedKey);
      }
      await widget.connManager.updateSshTunnel(connectionId, config);
      // Force the next connect to build a fresh tunnel with these settings.
      await SshTunnelService.instance.close(connectionId);
      SavedConnection.setSshResolvedBaseUrl(connectionId, null);
      if (mounted) {
        Navigator.of(context).pop(result.copyWith(ssh: config));
      }
    } catch (error) {
      _fail('Could not save the SSH settings: $error');
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return AlertDialog(
      title: Row(
        children: [
          const Icon(Icons.terminal, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              _isNew ? 'New SSH gateway' : 'SSH tunnel',
              style: theme.textTheme.titleMedium,
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: 400,
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Connects through an SSH host: the app runs '
                '"hermes gateway attach" there and forwards the gateway port to '
                'this device. No extra server process is started, and only the '
                'SSH port has to be reachable.',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              if (!_isNew)
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Connect over SSH'),
                  value: _enabled,
                  onChanged: _busy
                      ? null
                      : (value) => setState(() => _enabled = value),
                ),
              if (_enabled) ...[
                if (_isNew) ...[
                  TextField(
                    controller: _name,
                    enabled: !_busy,
                    decoration: const InputDecoration(
                      labelText: 'Gateway name',
                      hintText: 'Pi (SSH)',
                    ),
                  ),
                  const SizedBox(height: 8),
                ],
                Row(
                  children: [
                    Expanded(
                      flex: 3,
                      child: TextField(
                        controller: _host,
                        enabled: !_busy,
                        autocorrect: false,
                        decoration: const InputDecoration(
                          labelText: 'SSH host',
                          hintText: '192.168.0.24',
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: TextField(
                        controller: _port,
                        enabled: !_busy,
                        keyboardType: TextInputType.number,
                        decoration: const InputDecoration(labelText: 'Port'),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _user,
                  enabled: !_busy,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    labelText: 'SSH user',
                    hintText: 'torippy',
                  ),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _fingerprint,
                  enabled: !_busy,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    labelText: 'Host key fingerprint (optional)',
                    hintText: 'SHA256:…',
                  ),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _key,
                  enabled: !_busy,
                  maxLines: 5,
                  minLines: 3,
                  autocorrect: false,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  decoration: InputDecoration(
                    labelText: 'SSH private key',
                    hintText: '-----BEGIN OPENSSH PRIVATE KEY-----',
                    helperText: _hasStoredKey
                        ? 'A key is already stored. Leave blank to keep it.'
                        : 'Paste the whole key, including the BEGIN/END lines.',
                  ),
                ),
              ],
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(
                  _error!,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.error,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _busy ? null : () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _busy ? null : _save,
          child: Text(_busy ? 'Saving…' : 'Save'),
        ),
      ],
    );
  }
}
