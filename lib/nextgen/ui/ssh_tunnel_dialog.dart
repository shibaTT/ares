import 'package:flutter/material.dart';

import '../../core/models/connection.dart';
import '../../core/models/ssh_tunnel.dart';
import '../../core/services/connection_manager.dart';
import '../../core/services/ssh_key_store.dart';
import '../../core/services/ssh_tunnel_service.dart';

/// Opens the SSH tunnel editor for [connection].
///
/// Returns `true` when the settings were saved. The private key goes to the
/// platform secure store; only the host, port, user and an optional pinned
/// fingerprint are written to the connection metadata.
Future<bool> showSshTunnelDialog(
  BuildContext context, {
  required SavedConnection connection,
  required ConnectionManager connManager,
}) async {
  final saved = await showDialog<bool>(
    context: context,
    builder: (_) =>
        _SshTunnelDialog(connection: connection, connManager: connManager),
  );
  return saved ?? false;
}

class _SshTunnelDialog extends StatefulWidget {
  const _SshTunnelDialog({required this.connection, required this.connManager});

  final SavedConnection connection;
  final ConnectionManager connManager;

  @override
  State<_SshTunnelDialog> createState() => _SshTunnelDialogState();
}

class _SshTunnelDialogState extends State<_SshTunnelDialog> {
  late final TextEditingController _host;
  late final TextEditingController _port;
  late final TextEditingController _user;
  late final TextEditingController _fingerprint;
  late final TextEditingController _key;

  late bool _enabled;
  bool _hasStoredKey = false;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    final ssh = widget.connection.ssh;
    _enabled = ssh != null;
    _host = TextEditingController(text: ssh?.host ?? '');
    _port = TextEditingController(text: '${ssh?.port ?? 22}');
    _user = TextEditingController(text: ssh?.username ?? '');
    _fingerprint = TextEditingController(text: ssh?.hostKeySha256 ?? '');
    _key = TextEditingController();
    _loadStoredKey();
  }

  Future<void> _loadStoredKey() async {
    final has = await SshKeyStore.instance.hasKey(widget.connection.id);
    if (!mounted) return;
    setState(() => _hasStoredKey = has);
  }

  @override
  void dispose() {
    _host.dispose();
    _port.dispose();
    _user.dispose();
    _fingerprint.dispose();
    _key.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (!_enabled) {
        await widget.connManager.updateSshTunnel(widget.connection.id, null);
        await SshKeyStore.instance.deleteKey(widget.connection.id);
        await SshTunnelService.instance.close(widget.connection.id);
        SavedConnection.setSshResolvedBaseUrl(widget.connection.id, null);
        if (mounted) Navigator.of(context).pop(true);
        return;
      }

      final host = _host.text.trim();
      final user = _user.text.trim();
      final port = int.tryParse(_port.text.trim()) ?? 0;
      if (host.isEmpty || user.isEmpty || port <= 0) {
        setState(() {
          _error = 'SSH host, user and port are required.';
          _busy = false;
        });
        return;
      }

      final pastedKey = _key.text.trim();
      if (pastedKey.isEmpty && !_hasStoredKey) {
        setState(() {
          _error = 'Paste the SSH private key (OpenSSH or PEM, no passphrase).';
          _busy = false;
        });
        return;
      }
      if (pastedKey.isNotEmpty) {
        await SshKeyStore.instance.writeKey(widget.connection.id, pastedKey);
      }

      final fingerprint = _fingerprint.text.trim();
      await widget.connManager.updateSshTunnel(
        widget.connection.id,
        SshTunnelConfig(
          host: host,
          port: port,
          username: user,
          hostKeySha256: fingerprint.isEmpty ? null : fingerprint,
        ),
      );
      // Force the next connect to build a fresh tunnel with the new settings.
      await SshTunnelService.instance.close(widget.connection.id);
      SavedConnection.setSshResolvedBaseUrl(widget.connection.id, null);
      if (mounted) Navigator.of(context).pop(true);
    } catch (error) {
      setState(() {
        _error = 'Could not save the SSH settings: $error';
        _busy = false;
      });
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
          Expanded(child: Text('SSH tunnel', style: theme.textTheme.titleMedium)),
        ],
      ),
      content: SizedBox(
        width: 380,
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Reaches this connection through an SSH host: the app runs '
                '"hermes gateway attach" there and forwards the gateway port '
                'to this device. No extra server process is started.',
                style: theme.textTheme.bodySmall,
              ),
              const SizedBox(height: 12),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Connect over SSH'),
                value: _enabled,
                onChanged: _busy
                    ? null
                    : (value) => setState(() => _enabled = value),
              ),
              if (_enabled) ...[
                TextField(
                  controller: _user,
                  enabled: !_busy,
                  decoration: const InputDecoration(
                    labelText: 'SSH user',
                    hintText: 'torippy',
                  ),
                  autocorrect: false,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _host,
                  enabled: !_busy,
                  decoration: const InputDecoration(
                    labelText: 'SSH host',
                    hintText: '192.168.0.24',
                  ),
                  autocorrect: false,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _port,
                  enabled: !_busy,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(labelText: 'SSH port'),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _fingerprint,
                  enabled: !_busy,
                  decoration: const InputDecoration(
                    labelText: 'Host key fingerprint (optional)',
                    hintText: 'SHA256:…',
                  ),
                  autocorrect: false,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _key,
                  enabled: !_busy,
                  maxLines: 5,
                  minLines: 3,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  decoration: InputDecoration(
                    labelText: 'SSH private key',
                    hintText: '-----BEGIN OPENSSH PRIVATE KEY-----',
                    helperText: _hasStoredKey
                        ? 'A key is already stored. Leave blank to keep it.'
                        : 'Paste the whole key, including the BEGIN/END lines.',
                  ),
                  autocorrect: false,
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
