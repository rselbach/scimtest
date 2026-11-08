INSERT OR IGNORE INTO apps(id, environment_id, name, slug, protocol, scim_enabled, scim_base_url, scim_bearer_token, scim_auto_open_trace)
		SELECT 'migrated_scim_' || environments.id,
			environments.id,
			environments.name || ' SCIM',
			environments.slug || '-scim-' || substr(environments.id, -6),
			'scim', 1,
			base.value,
			COALESCE(token.value, ''),
			COALESCE(trace.value = '1', 0)
		FROM environments
		JOIN environment_config base ON base.environment_id = environments.id AND base.key = 'base_url' AND base.value != ''
		LEFT JOIN environment_config token ON token.environment_id = environments.id AND token.key = 'bearer_token'
		LEFT JOIN environment_config trace ON trace.environment_id = environments.id AND trace.key = 'auto_open_sync_trace'
		LEFT JOIN environment_config disabled ON disabled.environment_id = environments.id AND disabled.key = 'scim_disabled'
		WHERE COALESCE(disabled.value, '0') != '1'
		AND NOT EXISTS (SELECT 1 FROM apps WHERE apps.environment_id = environments.id);

UPDATE apps SET
		scim_base_url = COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'base_url'), ''),
		scim_bearer_token = COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'bearer_token'), ''),
		scim_auto_open_trace = COALESCE((SELECT value = '1' FROM environment_config WHERE environment_id = apps.environment_id AND key = 'auto_open_sync_trace'), 0),
		scim_enabled = CASE
			WHEN COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'base_url'), '') != ''
			 AND COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'scim_disabled'), '0') != '1'
			THEN 1 ELSE 0 END;

INSERT OR IGNORE INTO app_user_sync(app_id, user_id, remote_id, dirty, deleted, last_error)
		SELECT apps.id, users.id,
			CASE WHEN apps.environment_id = users.environment_id THEN users.remote_id ELSE '' END,
			CASE WHEN apps.environment_id = users.environment_id THEN users.dirty ELSE 1 END,
			users.deleted,
			CASE WHEN apps.environment_id = users.environment_id THEN users.last_error ELSE '' END
		FROM apps CROSS JOIN users WHERE apps.scim_enabled = 1;

INSERT OR IGNORE INTO app_group_sync(app_id, group_id, remote_id, dirty, deleted, last_error)
		SELECT apps.id, groups.id,
			CASE WHEN apps.environment_id = groups.environment_id THEN groups.remote_id ELSE '' END,
			CASE WHEN apps.environment_id = groups.environment_id THEN groups.dirty ELSE 1 END,
			groups.deleted,
			CASE WHEN apps.environment_id = groups.environment_id THEN groups.last_error ELSE '' END
		FROM apps CROSS JOIN groups WHERE apps.scim_enabled = 1;

INSERT OR REPLACE INTO config(key, value) VALUES('app_scim_migrated', '1');
