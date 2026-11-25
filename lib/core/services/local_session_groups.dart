import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

/// Device-only chat groups (開発 / 雑談 / …).
///
/// Hermes stores no per-session label (`session.mutate` only accepts title,
/// archived, hidden, pinned and unread), so groups live on this device and are
/// keyed per connection. The sidebar renders them as collapsible sections.
class LocalSessionGroups {
  static const keyPrefix = 'local_session_groups_v1_';

  final SharedPreferences _preferences;
  final String connectionId;

  LocalSessionGroups(this._preferences, {required this.connectionId});

  String get _key => '$keyPrefix$connectionId';

  /// Group name -> session ids, in the order the groups were created.
  Map<String, List<String>> load() {
    final raw = _preferences.getString(_key);
    if (raw == null || raw.isEmpty) return <String, List<String>>{};
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return <String, List<String>>{};
      final groups = <String, List<String>>{};
      for (final entry in decoded.entries) {
        final name = entry.key;
        final ids = entry.value;
        if (name is! String || name.isEmpty || ids is! List) continue;
        groups[name] = [
          for (final id in ids)
            if (id is String && id.isNotEmpty) id,
        ];
      }
      return groups;
    } catch (_) {
      return <String, List<String>>{};
    }
  }

  /// The group [sessionId] currently sits in, if any.
  String? groupOf(String sessionId, {Map<String, List<String>>? groups}) {
    final all = groups ?? load();
    for (final entry in all.entries) {
      if (entry.value.contains(sessionId)) return entry.key;
    }
    return null;
  }

  /// Puts [sessionId] in [group] (creating it), or in no group when null.
  Future<Map<String, List<String>>> assign(
    String sessionId,
    String? group,
  ) async {
    if (sessionId.isEmpty) throw ArgumentError.value(sessionId, 'sessionId');
    final name = group?.trim() ?? '';
    final next = <String, List<String>>{};
    for (final entry in load().entries) {
      final ids = [
        for (final id in entry.value)
          if (id != sessionId) id,
      ];
      // Keep empty groups: an empty one is a place to file the next chat.
      if (entry.key == name) ids.insert(0, sessionId);
      next[entry.key] = ids;
    }
    if (name.isNotEmpty && !next.containsKey(name)) {
      next[name] = [sessionId];
    }
    await _save(next);
    return next;
  }

  /// Drops a group; its chats become ungrouped.
  Future<Map<String, List<String>>> removeGroup(String name) async {
    final next = load()..remove(name);
    await _save(next);
    return next;
  }

  Future<void> _save(Map<String, List<String>> groups) async {
    final saved = await _preferences.setString(
      _key,
      jsonEncode({
        for (final entry in groups.entries) entry.key: entry.value,
      }),
    );
    if (!saved) throw StateError('Could not save chat groups on this device');
  }
}
