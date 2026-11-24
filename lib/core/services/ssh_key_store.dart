import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Stores the SSH private key for each connection in the platform secure store.
///
/// The key never lands in shared preferences or the connection metadata JSON:
/// only the SSH host, port, user and an optional pinned fingerprint do.
class SshKeyStore {
  SshKeyStore._();

  static final SshKeyStore instance = SshKeyStore._();

  static const _options = AndroidOptions(
    resetOnError: false,
    migrateWithBackup: true,
    storageNamespace: 'hermes_android_ssh',
  );

  static const String _prefix = 'ssh_private_key.';

  final FlutterSecureStorage _storage = const FlutterSecureStorage(
    aOptions: _options,
  );

  String _slot(String connectionId) => '$_prefix$connectionId';

  /// Reads the stored private key (PEM / OpenSSH text) for [connectionId].
  Future<String?> readKey(String connectionId) async {
    final value = await _storage.read(key: _slot(connectionId));
    final trimmed = value?.trim();
    return trimmed == null || trimmed.isEmpty ? null : trimmed;
  }

  /// Stores [privateKeyPem] for [connectionId]. An empty value deletes it.
  Future<void> writeKey(String connectionId, String privateKeyPem) async {
    final trimmed = privateKeyPem.trim();
    if (trimmed.isEmpty) {
      await deleteKey(connectionId);
      return;
    }
    await _storage.write(key: _slot(connectionId), value: trimmed);
  }

  /// Removes the stored key for [connectionId].
  Future<void> deleteKey(String connectionId) =>
      _storage.delete(key: _slot(connectionId));

  /// Whether a key is stored for [connectionId].
  Future<bool> hasKey(String connectionId) async =>
      (await readKey(connectionId)) != null;
}
