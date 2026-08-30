'use strict';
'require view';
'require fs';
'require ui';

return view.extend({
	load: function() {
		return Promise.all([
			fs.exec('/usr/bin/dns-checker-engine', ['status']),
			fs.exec('/usr/bin/dns-checker-engine', ['backup'])
		]).then(function(results) {
			var statusData = {};
			try {
				var raw = (results[0].stdout || '{}').replace(/[\x00-\x1F\x7F]/g, function(c) {
					return (c === '\t' || c === '\n' || c === '\r') ? ' ' : '';
				});
				statusData = JSON.parse(raw);
			} catch (e) {}
			return statusData;
		});
	},

	render: function(initialStatus) {
		// =========================================================================
		// 1. Centralized State Store
		// =========================================================================
		var defaultProviders = [
			{ id: 'comss', name: 'COMSS One', location: 'RU MSK', udp: '83.220.169.155', doh: 'https://dns.comss.one/dns-query', dot: 'dns.comss.one', boot: '77.88.8.8' },
			{ id: 'nextdns', name: 'NextDNS', location: 'Anycast', udp: '45.90.28.80', doh: 'https://dns.nextdns.io/dns-query', dot: 'dns.nextdns.io', boot: '77.88.8.8' },
			{ id: 'adguard', name: 'AdGuard DNS', location: 'SE ARN', udp: '94.140.14.14', doh: 'https://dns.adguard-dns.com/dns-query', dot: 'dns.adguard-dns.com', boot: '77.88.8.8' },
			{ id: 'cloudflare', name: 'Cloudflare', location: 'RU MSK', udp: '1.1.1.1', doh: 'https://cloudflare-dns.com/dns-query', dot: '1.1.1.1', boot: '77.88.8.8' },
			{ id: 'google', name: 'Google Public', location: 'Anycast', udp: '8.8.8.8', doh: 'https://dns.google/dns-query', dot: 'dns.google', boot: '77.88.8.8' },
			{ id: 'quad9', name: 'Quad9', location: 'FI HEL', udp: '9.9.9.9', doh: 'https://dns.quad9.net/dns-query', dot: 'dns.quad9.net', boot: '77.88.8.8' },
			{ id: 'yandex', name: 'Yandex DNS', location: 'RU MSK', udp: '77.88.8.8', doh: 'https://common.dot.dns.yandex.net/dns-query', dot: 'common.dot.dns.yandex.net', boot: '77.88.8.8' }
		];

		var state = {
			version: initialStatus.version || '1.1.0',
			podkopRunning: !!initialStatus.podkop_running,
			activePrimaryServer: (initialStatus.podkop && initialStatus.podkop.dns_server) || '',
			activePrimaryProto: (initialStatus.podkop && initialStatus.podkop.dns_type) || 'udp',
			activeBackupServer: (initialStatus.podkop && initialStatus.podkop.backup_dns_server) || '',
			activeBackupProto: (initialStatus.podkop && initialStatus.podkop.backup_dns_type) || 'udp',
			activeWanDns: initialStatus.router_wan_dns || '',
			customProviders: initialStatus.custom_providers || [],
			providersList: [],
			selected: {
				primaryId: 'comss',
				primaryProto: (initialStatus.podkop && initialStatus.podkop.dns_type) || 'udp',
				backupId: 'none',
				backupProto: (initialStatus.podkop && initialStatus.podkop.backup_dns_type) || 'udp',
				wan1Id: 'auto',
				wan2Id: 'none'
			},
			benchmark: null,
			recommendations: null,
			leakResult: null,
			leakLoading: false,
			updateInfo: null,
			benchLoading: false
		};

		function rebuildProvidersList() {
			var list = defaultProviders.slice();
			state.customProviders.forEach(function(cp) {
				list.push({
					id: cp.id,
					name: cp.name + ' [Кастом]',
					location: 'Custom',
					udp: cp.udp || '0.0.0.0',
					doh: cp.doh || '',
					dot: cp.dot || '',
					boot: cp.boot || '77.88.8.8',
					is_custom: true
				});
			});
			state.providersList = list;

			// Auto-match initial selections
			if (state.activePrimaryServer) {
				list.forEach(function(p) {
					if (p.udp === state.activePrimaryServer || p.doh === state.activePrimaryServer || p.dot === state.activePrimaryServer) {
						state.selected.primaryId = p.id;
					}
				});
			}
			if (state.activeBackupServer) {
				list.forEach(function(p) {
					if (p.udp === state.activeBackupServer || p.doh === state.activeBackupServer || p.dot === state.activeBackupServer) {
						state.selected.backupId = p.id;
					}
				});
			}
			if (state.activeWanDns) {
				var wanParts = state.activeWanDns.trim().split(/\s+/);
				if (wanParts.length > 0) {
					list.forEach(function(p) { if (p.udp === wanParts[0]) state.selected.wan1Id = p.id; });
				}
				if (wanParts.length > 1) {
					list.forEach(function(p) { if (p.udp === wanParts[1]) state.selected.wan2Id = p.id; });
				}
			}
		}

		rebuildProvidersList();

		// Helper: safe JSON parsing
		function safeJsonParse(str) {
			if (!str) return {};
			var sanitized = str.replace(/[\x00-\x1F\x7F]/g, function(c) {
				return (c === '\t' || c === '\n' || c === '\r') ? ' ' : '';
			});
			return JSON.parse(sanitized);
		}

		function getProvidersMap() {
			var map = {};
			state.providersList.forEach(function(p) { map[p.id] = p; });
			return map;
		}

		function getWanIp(id) {
			if (!id || id === 'auto' || id === 'none') return '';
			var map = getProvidersMap();
			return (map[id] && map[id].udp) || '';
		}

		function findProviderLabel(addr, proto) {
			if (!addr || addr === 'none') return _('Не настроен');
			var pName = addr;
			for (var i = 0; i < state.providersList.length; i++) {
				var p = state.providersList[i];
				if (p.udp === addr || p.doh === addr || p.dot === addr) {
					pName = p.name + ' [' + addr + ']';
					break;
				}
			}
			return pName + (proto ? ' (' + proto.toUpperCase() + ')' : '');
		}

		// =========================================================================
		// 2. Action Handlers (Mutate State and Trigger Render)
		// =========================================================================
		var actions = {
			refreshStatus: function() {
				return fs.exec('/usr/bin/dns-checker-engine', ['status']).then(function(res) {
					var st = safeJsonParse(res.stdout);
					state.podkopRunning = !!st.podkop_running;
					state.activePrimaryServer = (st.podkop && st.podkop.dns_server) || '';
					state.activePrimaryProto = (st.podkop && st.podkop.dns_type) || 'udp';
					state.activeBackupServer = (st.podkop && st.podkop.backup_dns_server) || '';
					state.activeBackupProto = (st.podkop && st.podkop.backup_dns_type) || 'udp';
					state.activeWanDns = st.router_wan_dns || '';
					state.customProviders = st.custom_providers || [];
					rebuildProvidersList();
					render();
				});
			},

			runLeakTest: function() {
				state.leakLoading = true;
				render();
				fs.exec('/usr/bin/dns-checker-engine', ['leak_test']).then(function(res) {
					state.leakLoading = false;
					try {
						state.leakResult = safeJsonParse(res.stdout);
					} catch (e) {
						state.leakResult = { error: true };
					}
					render();
				});
			},

			runBenchmark: function() {
				state.benchLoading = true;
				render();
				ui.showIndicator('dns-bench', _('Замер задержек (10 пакетов на узел)...'));

				fs.exec('/usr/bin/dns-checker-engine', ['test'], null, 60000).then(function(res) {
					ui.hideIndicator('dns-bench');
					state.benchLoading = false;
					try {
						var data = safeJsonParse(res.stdout);
						state.benchmark = data;

						// Compute recommendations
						var pairs = [];
						if (data && data.providers) {
							data.providers.forEach(function(p) {
								['udp', 'doh', 'dot'].forEach(function(proto) {
									if (p[proto] && p[proto].latency >= 0 && !(proto === 'udp' && p.hijacked)) {
										pairs.push({
											id: p.id,
											name: p.name,
											proto: proto,
											latency: p[proto].latency,
											address: p[proto].address,
											ip: p.udp
										});
									}
								});
							});
						}

						if (pairs.length >= 2) {
							pairs.sort(function(a, b) { return a.latency - b.latency; });
							var bestP = pairs[0];
							var bestB = null;
							for (var i = 1; i < pairs.length; i++) {
								if (pairs[i].id !== bestP.id) {
									bestB = pairs[i];
									break;
								}
							}
							if (!bestB) bestB = pairs[1];

							state.recommendations = { primary: bestP, backup: bestB };

							// Auto-fill form selections immediately
							state.selected.primaryId = bestP.id;
							state.selected.primaryProto = bestP.proto;
							state.selected.backupId = bestB.id;
							state.selected.backupProto = bestB.proto;
							state.selected.wan1Id = bestP.id;
							state.selected.wan2Id = bestB.id;
						}

						ui.addNotification(null, E('p', {}, _('Замер завершен! Рекомендуемые серверы автоматически выставлены в форму.')), 'info');
					} catch (err) {
						ui.addNotification(null, E('p', {}, _('Ошибка парсинга результатов замера: ') + err), 'error');
					}
					render();
				}).catch(function(err) {
					ui.hideIndicator('dns-bench');
					state.benchLoading = false;
					ui.addNotification(null, E('p', {}, _('Сбой запуска теста: ') + err), 'error');
					render();
				});
			},

			applyRecommendations: function() {
				if (!state.recommendations) return;
				var r = state.recommendations;
				state.selected.primaryId = r.primary.id;
				state.selected.primaryProto = r.primary.proto;
				state.selected.backupId = r.backup.id;
				state.selected.backupProto = r.backup.proto;
				state.selected.wan1Id = r.primary.id;
				state.selected.wan2Id = r.backup.id;
				render();
				ui.addNotification(null, E('p', {}, _('Рекомендуемые серверы подставлены в форму!')), 'info');
			},

			applyPrimary: function() {
				var map = getProvidersMap();
				var obj = map[state.selected.primaryId] || map['comss'];
				var addr = obj[state.selected.primaryProto] || obj['udp'];
				ui.showIndicator('apply-p', _('Применение основного DNS Podkop...'));
				fs.exec('/usr/bin/dns-checker-engine', ['apply_primary', state.selected.primaryProto, addr, obj.boot]).then(function() {
					ui.hideIndicator('apply-p');
					actions.refreshStatus();
					ui.addNotification(null, E('p', {}, _('Основной DNS Podkop успешно сохранен!')), 'info');
				});
			},

			applyBackup: function() {
				var map = getProvidersMap();
				var addr = 'none';
				if (state.selected.backupId !== 'none' && map[state.selected.backupId]) {
					addr = map[state.selected.backupId][state.selected.backupProto] || map[state.selected.backupId]['udp'];
				}
				ui.showIndicator('apply-b', _('Применение резервного DNS Podkop...'));
				fs.exec('/usr/bin/dns-checker-engine', ['apply_backup', state.selected.backupProto, addr]).then(function() {
					ui.hideIndicator('apply-b');
					actions.refreshStatus();
					ui.addNotification(null, E('p', {}, _('Резервный DNS Podkop успешно сохранен!')), 'info');
				});
			},

			applyWan: function() {
				var ip1 = getWanIp(state.selected.wan1Id);
				var ip2 = getWanIp(state.selected.wan2Id);
				ui.showIndicator('apply-w', _('Применение DNS роутера (WAN)...'));
				fs.exec('/usr/bin/dns-checker-engine', ['apply_wan', ip1, ip2]).then(function() {
					ui.hideIndicator('apply-w');
					actions.refreshStatus();
					ui.addNotification(null, E('p', {}, _('DNS роутера (WAN) успешно сохранен!')), 'info');
				});
			},

			applyAll: function() {
				var map = getProvidersMap();
				var pObj = map[state.selected.primaryId] || map['comss'];
				var pAddr = pObj[state.selected.primaryProto] || pObj['udp'];
				var bootAddr = pObj.boot || '77.88.8.8';

				var bAddr = 'none';
				if (state.selected.backupId !== 'none' && map[state.selected.backupId]) {
					bAddr = map[state.selected.backupId][state.selected.backupProto] || map[state.selected.backupId]['udp'];
				}

				var ip1 = getWanIp(state.selected.wan1Id);
				var ip2 = getWanIp(state.selected.wan2Id);

				var args = ['apply', state.selected.primaryProto, pAddr, bootAddr, state.selected.backupProto, bAddr, ip1, ip2];

				ui.showIndicator('dns-apply', _('Применение всех настроек DNS...'));
				fs.exec('/usr/bin/dns-checker-engine', args).then(function(res) {
					ui.hideIndicator('dns-apply');
					var out = safeJsonParse(res.stdout);
					actions.refreshStatus();
					ui.addNotification(null, E('p', {}, out.message || _('Все настройки DNS успешно применены!')), out.status === 'error' ? 'error' : 'info');
				});
			},

			restoreBackup: function() {
				if (!confirm(_('Вы уверены, что хотите откатить настройки DNS до исходного состояния?'))) return;
				ui.showIndicator('dns-restore', _('Откат настроек...'));
				fs.exec('/usr/bin/dns-checker-engine', ['restore']).then(function() {
					ui.hideIndicator('dns-restore');
					actions.refreshStatus();
					ui.addNotification(null, E('p', {}, _('Настройки успешно восстановлены из бэкапа.')), 'info');
				});
			},

			checkUpdate: function() {
				ui.showIndicator('dns-update-check', _('Проверка версии на GitHub...'));
				fs.exec('/usr/bin/dns-checker-engine', ['check_update']).then(function(res) {
					ui.hideIndicator('dns-update-check');
					state.updateInfo = safeJsonParse(res.stdout);
					render();
				});
			},

			runUpdate: function() {
				ui.showIndicator('dns-update-run', _('Загрузка и установка обновления...'));
				fs.exec('/usr/bin/dns-checker-engine', ['update']).then(function() {
					ui.hideIndicator('dns-update-run');
					ui.addNotification(null, E('p', {}, _('Плагин успешно обновлен!')), 'info');
					window.setTimeout(function() { location.reload(); }, 1200);
				});
			},

			addCustom: function(name, doh, dot, udp) {
				if (!name) {
					ui.addNotification(null, E('p', {}, _('Укажите название профиля.')), 'error');
					return;
				}
				if (!doh && !dot && !udp) {
					ui.addNotification(null, E('p', {}, _('Укажите хотя бы один протокол (DoH, DoT или UDP IP).')), 'error');
					return;
				}
				var id = 'c_' + Date.now();
				fs.exec('/usr/bin/dns-checker-engine', ['add_custom', id, name, udp, doh, dot]).then(function() {
					ui.addNotification(null, E('p', {}, _('Профиль успешно добавлен!')), 'info');
					actions.refreshStatus();
				});
			},

			deleteCustom: function(id, name) {
				if (!confirm(_('Удалить профиль ') + name + '?')) return;
				fs.exec('/usr/bin/dns-checker-engine', ['del_custom', id]).then(function() {
					ui.addNotification(null, E('p', {}, _('Профиль удален.')), 'info');
					actions.refreshStatus();
				});
			}
		};

		// =========================================================================
		// 3. Pure Functional Components (Zero appendChild!)
		// =========================================================================

		// Component: Header
		function HeaderComponent() {
			return E('div', {}, [
				E('div', { 'style': 'display: flex; align-items: baseline; justify-content: space-between;' }, [
					E('h2', {}, _('DNS Benchmark & Security Monitor')),
					E('span', { 'style': 'font-size: 12px; color: #888;' }, 'v' + state.version)
				]),
				E('div', { 'class': 'cbi-map-descr' },
					_('Замер задержек (10 пакетов), детекция перехвата DNS (Hijacking), утечек (Leak Test), Anycast-локаций и раздельное управление DNS.')
				)
			]);
		}

		// Component: Status Card
		function StatusCardComponent() {
			var leakNode = null;
			if (state.leakResult) {
				if (state.leakResult.error) {
					leakNode = E('div', {
						'style': 'margin-top: 10px; padding: 10px 14px; border-radius: 6px; font-size: 13px; background: rgba(220, 53, 69, 0.15); border: 1px solid #dc3545;'
					}, _('Ошибка проведения Leak Test.'));
				} else {
					leakNode = E('div', {
						'style': 'margin-top: 10px; padding: 10px 14px; border-radius: 6px; font-size: 13px; background: rgba(40, 167, 69, 0.15); border: 1px solid #28a745;'
					}, [
						E('span', { 'style': 'font-weight: bold; color: #28a745;' }, '✔ Утечек DNS не обнаружено! '),
						E('span', {}, 'Фактический внешний резолвер: '),
						E('code', {}, state.leakResult.resolver_ip + ' (' + state.leakResult.provider + ')')
					]);
				}
			}

			var statusChildren = [
				E('div', { 'style': 'display: flex; justify-content: space-between; align-items: center;' }, [
					E('h3', { 'style': 'margin: 0;' }, _('Текущий статус сети')),
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'style': 'font-size: 12px; height: 32px; padding: 0 12px;',
						'disabled': state.leakLoading ? 'disabled' : null,
						'click': function() { actions.runLeakTest(); }
					}, state.leakLoading ? _('Проверка утечек...') : _('🔍 Проверить утечки DNS (Leak Test)'))
				]),
				E('div', { 'class': 'table', 'style': 'margin-top: 15px; margin-bottom: 5px;' }, [
					E('div', { 'class': 'tr' }, [
						E('div', { 'class': 'td left', 'style': 'font-weight: bold; width: 240px;' }, _('Служба Podkop:')),
						E('div', { 'class': 'td left' }, state.podkopRunning ? 
							E('span', { 'class': 'badge', 'style': 'background:#28a745; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold;' }, _('Активна')) :
							E('span', { 'class': 'badge', 'style': 'background:#6c757d; color:#fff; padding:3px 8px; border-radius:4px;' }, _('Не запущена')))
					]),
					E('div', { 'class': 'tr' }, [
						E('div', { 'class': 'td left', 'style': 'font-weight: bold;' }, _('Основной DNS Podkop:')),
						E('div', { 'class': 'td left' }, E('code', {}, findProviderLabel(state.activePrimaryServer, state.activePrimaryProto)))
					]),
					E('div', { 'class': 'tr' }, [
						E('div', { 'class': 'td left', 'style': 'font-weight: bold;' }, _('Резервный DNS Podkop:')),
						E('div', { 'class': 'td left' }, E('code', {}, findProviderLabel(state.activeBackupServer, state.activeBackupProto)))
					]),
					E('div', { 'class': 'tr' }, [
						E('div', { 'class': 'td left', 'style': 'font-weight: bold;' }, _('DNS роутера (WAN):')),
						E('div', { 'class': 'td left' }, E('code', {}, state.activeWanDns ? state.activeWanDns : _('Автоматический от провайдера (DHCP)')))
					])
				])
			];
			if (leakNode) statusChildren.push(leakNode);
			return E('div', { 'class': 'cbi-section' }, statusChildren);
		}

		// Component: Recommendations Banner
		function RecommendationsComponent() {
			if (!state.recommendations) return null;
			var r = state.recommendations;

			return E('div', { 'class': 'cbi-section', 'style': 'margin-bottom: 15px;' }, [
				E('div', {
					'style': 'background: rgba(40, 167, 69, 0.12); border: 1px solid #28a745; border-radius: 8px; padding: 15px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 14px;'
				}, [
					E('div', { 'style': 'line-height: 1.6;' }, [
						E('div', { 'style': 'font-weight: bold; color: #28a745; font-size: 14px; margin-bottom: 6px;' }, _('💡 Рекомендация по 10 замерам (среднее значение):')),
						E('div', { 'style': 'font-size: 13px;' }, [
							E('div', {}, [
								E('span', { 'style': 'color: #28a745; margin-right: 6px;' }, '•'),
								_('Лучший основной Podkop: '),
								E('strong', {}, r.primary.name + ' [' + r.primary.proto.toUpperCase() + ': ' + r.primary.latency + ' мс]')
							]),
							E('div', {}, [
								E('span', { 'style': 'color: #28a745; margin-right: 6px;' }, '•'),
								_('Резервный Podkop: '),
								E('strong', {}, r.backup.name + ' [' + r.backup.proto.toUpperCase() + ': ' + r.backup.latency + ' мс]')
							]),
							E('div', {}, [
								E('span', { 'style': 'color: #28a745; margin-right: 6px;' }, '•'),
								_('Резервный WAN DNS: '),
								E('strong', {}, r.primary.name + ' + ' + r.backup.name)
							])
						]),
						E('div', { 'style': 'font-size: 11px; color: #aaa; margin-top: 6px;' },
							_('Параметры автоматически выставлены в поля формы ниже. Нажмите «Применить всё сразу» для активации.')
						)
					]),
					E('button', {
						'class': 'cbi-button cbi-button-save',
						'style': 'background: #28a745; border-color: #28a745; font-weight: bold; height: 38px; padding: 0 18px;',
						'click': function() { actions.applyRecommendations(); }
					}, _('Выбрать рекомендуемые'))
				])
			]);
		}

		// Helper: format latency badge
		function formatBadge(metric, isHijacked) {
			if (!metric || typeof metric.latency !== 'number') {
				return E('span', { 'style': 'color: #888; font-weight: bold;' }, '—');
			}
			if (metric.latency < 0) {
				return E('span', { 'style': 'color: #dc3545; font-weight: bold;' }, '✕ сбой');
			}
			if (isHijacked) {
				return E('span', {
					'style': 'background: #dc3545; color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: bold;'
				}, '⚠ Перехват (' + metric.latency + ' мс)');
			}
			var lat = metric.latency;
			var color = lat < 25 ? '#28a745' : (lat < 80 ? '#ffc107; color: #000' : '#fd7e14');
			return E('span', {
				'style': 'background: ' + color + '; color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: bold;'
			}, lat + ' мс');
		}

		// Component: Benchmark Table
		function BenchmarkTableComponent() {
			var pMap = {};
			if (state.benchmark && state.benchmark.providers) {
				state.benchmark.providers.forEach(function(item) { pMap[item.id] = item; });
			}

			var rows = state.providersList.map(function(p) {
				var metricObj = pMap[p.id] || {};
				var loc = metricObj.location || p.location || 'Anycast';
				var isH = !!metricObj.hijacked;

				var nameItems = [
					E('strong', {}, p.name),
					E('span', {
						'style': 'font-size: 11px; background: rgba(255, 255, 255, 0.08); padding: 1px 6px; border-radius: 4px; font-weight: 500;'
					}, loc)
				];
				if (isH) {
					nameItems.push(E('span', {
						'style': 'font-size: 10px; background: #dc3545; color: #fff; padding: 1px 5px; border-radius: 3px; font-weight: bold;'
					}, _('⚠ ПЕРЕХВАТ')));
				}

				return E('tr', { 'class': 'tr cbi-rowstyle-1' }, [
					E('td', { 'class': 'td' }, [
						E('div', { 'style': 'display: flex; align-items: center; gap: 6px;' }, nameItems),
						E('div', { 'style': 'font-size: 11px; color: #777; margin-top: 2px;' }, (p.udp && p.udp !== '0.0.0.0') ? p.udp : p.doh)
					]),
					E('td', { 'class': 'td', 'style': 'text-align:center;' }, formatBadge(metricObj.udp, isH)),
					E('td', { 'class': 'td', 'style': 'text-align:center;' }, formatBadge(metricObj.doh, false)),
					E('td', { 'class': 'td', 'style': 'text-align:center;' }, formatBadge(metricObj.dot, false))
				]);
			});

			return E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table', 'style': 'width: 100%; text-align: left;' }, [
					E('thead', {}, [
						E('tr', { 'class': 'tr cbi-section-table-titles' }, [
							E('th', { 'class': 'th' }, _('Провайдер и локация')),
							E('th', { 'class': 'th', 'style': 'text-align:center;' }, _('UDP (порт 53)')),
							E('th', { 'class': 'th', 'style': 'text-align:center;' }, _('DoH (порт 443)')),
							E('th', { 'class': 'th', 'style': 'text-align:center;' }, _('DoT (порт 853)'))
						])
					]),
					E('tbody', {}, rows)
				])
			]);
		}

		// Component: Custom DNS Profiles
		function CustomDnsComponent() {
			var nameInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'Мой NextDNS / AdGuard', 'style': 'width: 180px;' });
			var dohInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'https://dns.nextdns.io/xxxxxx', 'style': 'width: 240px;' });
			var dotInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'xxxxxx.dns.nextdns.io', 'style': 'width: 200px;' });
			var udpInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': '45.90.28.80 (необязательно)', 'style': 'width: 160px;' });

			var listTable = null;
			if (state.customProviders.length === 0) {
				listTable = E('div', { 'style': 'font-size: 13px; color: #888;' }, _('Пользовательские DNS-профили пока не добавлены.'));
			} else {
				var rows = state.customProviders.map(function(cp) {
					return E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td' }, E('strong', {}, cp.name)),
						E('td', { 'class': 'td' }, E('code', {}, cp.doh || '—')),
						E('td', { 'class': 'td' }, E('code', {}, cp.dot || '—')),
						E('td', { 'class': 'td' }, E('code', {}, cp.udp || '—')),
						E('td', { 'class': 'td', 'style': 'text-align: right;' }, [
							E('button', {
								'class': 'cbi-button cbi-button-remove',
								'style': 'height: 28px; padding: 0 10px; font-size: 11px;',
								'click': function() { actions.deleteCustom(cp.id, cp.name); }
							}, _('Удалить'))
						])
					]);
				});

				listTable = E('table', { 'class': 'table', 'style': 'width: 100%; font-size: 13px;' }, [
					E('thead', {}, [
						E('tr', { 'class': 'tr cbi-section-table-titles' }, [
							E('th', { 'class': 'th' }, _('Название')),
							E('th', { 'class': 'th' }, _('DoH эндпоинт')),
							E('th', { 'class': 'th' }, _('DoT хост')),
							E('th', { 'class': 'th' }, _('UDP IP')),
							E('th', { 'class': 'th', 'style': 'text-align: right;' }, _('Действие'))
						])
					]),
					E('tbody', {}, rows)
				]);
			}

			return E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('Пользовательские DNS-профили (NextDNS, AdGuard Home, Control D)')),
				E('div', { 'class': 'cbi-map-descr' },
					_('Добавьте собственный DNS-сервер. Он автоматически появится в таблице замера, селекторах и блоке рекомендаций.')
				),
				E('div', { 'style': 'display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 15px; margin-bottom: 15px;' }, [
					nameInput,
					dohInput,
					dotInput,
					udpInput,
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'style': 'height: 36px; padding: 0 16px;',
						'click': function() {
							actions.addCustom(nameInput.value.trim(), dohInput.value.trim(), dotInput.value.trim(), udpInput.value.trim());
						}
					}, _('+ Добавить профиль'))
				]),
				E('div', { 'style': 'margin-top: 15px;' }, [listTable])
			]);
		}

		// Component: Config Grid & Actions
		function ConfigSectionComponent() {
			var selectStyle = 'width: 100%; min-height: 38px; padding: 4px 8px; font-size: 13px; line-height: 1.5; box-sizing: border-box;';
			var btnStyle = 'width: 100%; min-height: 38px; height: 38px; font-size: 12px; font-weight: 600; padding: 0 6px; box-sizing: border-box; display: inline-flex; align-items: center; justify-content: center;';

			// 1. Primary Podkop
			var primarySelect = E('select', {
				'class': 'cbi-input-select',
				'style': selectStyle,
				'change': function(ev) { state.selected.primaryId = ev.target.value; }
			}, state.providersList.map(function(p) {
				return E('option', {
					'value': p.id,
					'selected': (p.id === state.selected.primaryId) ? 'selected' : null
				}, p.name);
			}));

			var primaryProtoSelect = E('select', {
				'class': 'cbi-input-select',
				'style': selectStyle,
				'change': function(ev) { state.selected.primaryProto = ev.target.value; }
			}, [
				E('option', { 'value': 'udp', 'selected': (state.selected.primaryProto === 'udp') ? 'selected' : null }, 'UDP (порт 53)'),
				E('option', { 'value': 'doh', 'selected': (state.selected.primaryProto === 'doh') ? 'selected' : null }, 'DoH (порт 443)'),
				E('option', { 'value': 'dot', 'selected': (state.selected.primaryProto === 'dot') ? 'selected' : null }, 'DoT (порт 853)')
			]);

			// 2. Backup Podkop
			var backupOptions = [
				E('option', {
					'value': 'none',
					'selected': (state.selected.backupId === 'none') ? 'selected' : null
				}, _('Без резервного'))
			];
			state.providersList.forEach(function(p) {
				backupOptions.push(E('option', {
					'value': p.id,
					'selected': (p.id === state.selected.backupId) ? 'selected' : null
				}, p.name));
			});

			var backupSelect = E('select', {
				'class': 'cbi-input-select',
				'style': selectStyle,
				'change': function(ev) { state.selected.backupId = ev.target.value; }
			}, backupOptions);

			var backupProtoSelect = E('select', {
				'class': 'cbi-input-select',
				'style': selectStyle,
				'change': function(ev) { state.selected.backupProto = ev.target.value; }
			}, [
				E('option', { 'value': 'udp', 'selected': (state.selected.backupProto === 'udp') ? 'selected' : null }, 'UDP (порт 53)'),
				E('option', { 'value': 'doh', 'selected': (state.selected.backupProto === 'doh') ? 'selected' : null }, 'DoH (порт 443)'),
				E('option', { 'value': 'dot', 'selected': (state.selected.backupProto === 'dot') ? 'selected' : null }, 'DoT (порт 853)')
			]);

			// 3. WAN DNS 1 & 2
			var wan1Options = [
				E('option', {
					'value': 'auto',
					'selected': (state.selected.wan1Id === 'auto') ? 'selected' : null
				}, _('Автоматический (DHCP)'))
			];
			state.providersList.forEach(function(p) {
				if (p.udp && p.udp !== '0.0.0.0') {
					wan1Options.push(E('option', {
						'value': p.id,
						'selected': (p.id === state.selected.wan1Id) ? 'selected' : null
					}, p.name + ' (' + p.udp + ')'));
				}
			});
			var wan1Select = E('select', {
				'class': 'cbi-input-select',
				'style': selectStyle,
				'change': function(ev) { state.selected.wan1Id = ev.target.value; }
			}, wan1Options);

			var wan2Options = [
				E('option', {
					'value': 'none',
					'selected': (state.selected.wan2Id === 'none') ? 'selected' : null
				}, _('Без второго DNS'))
			];
			state.providersList.forEach(function(p) {
				if (p.udp && p.udp !== '0.0.0.0') {
					wan2Options.push(E('option', {
						'value': p.id,
						'selected': (p.id === state.selected.wan2Id) ? 'selected' : null
					}, p.name + ' (' + p.udp + ')'));
				}
			});
			var wan2Select = E('select', {
				'class': 'cbi-input-select',
				'style': selectStyle,
				'change': function(ev) { state.selected.wan2Id = ev.target.value; }
			}, wan2Options);

			var grid = E('div', {
				'style': 'display: grid; grid-template-columns: 200px 1fr 155px 155px; gap: 14px 12px; align-items: center; width: 100%; box-sizing: border-box; margin-top: 15px;'
			}, [
				E('div', { 'style': 'font-weight: 600; white-space: nowrap;' }, _('1. Основной DNS Podkop:')),
				primarySelect,
				primaryProtoSelect,
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'style': btnStyle,
					'click': function() { actions.applyPrimary(); }
				}, _('Применить основной')),

				E('div', { 'style': 'font-weight: 600; white-space: nowrap;' }, _('2. Резервный DNS Podkop:')),
				backupSelect,
				backupProtoSelect,
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'style': btnStyle,
					'click': function() { actions.applyBackup(); }
				}, _('Применить резервный')),

				E('div', { 'style': 'font-weight: 600; white-space: nowrap;' }, _('3. DNS роутера (WAN):')),
				wan1Select,
				wan2Select,
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'style': btnStyle,
					'click': function() { actions.applyWan(); }
				}, _('Применить WAN DNS'))
			]);

			// Update Banner (declarative)
			var updateBanner = null;
			if (state.updateInfo) {
				if (state.updateInfo.has_update) {
					updateBanner = E('div', {
						'style': 'margin-top: 15px; padding: 12px 16px; border-radius: 6px; font-size: 13px; background: rgba(40, 167, 69, 0.15); border: 1px solid #28a745;'
					}, [
						E('div', { 'style': 'display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;' }, [
							E('div', {}, [
								E('strong', { 'style': 'color: #28a745;' }, _('Доступно обновление! ')),
								E('span', {}, _('Установлена: ') + 'v' + state.updateInfo.local_version + ' | ' + _('На GitHub: ') + 'v' + state.updateInfo.remote_version)
							]),
							E('button', {
								'class': 'cbi-button cbi-button-save',
								'style': 'height: 32px; padding: 0 12px; font-weight: bold;',
								'click': function() { actions.runUpdate(); }
							}, _('⬇ Установить обновление'))
						])
					]);
				} else {
					updateBanner = E('div', {
						'style': 'margin-top: 15px; padding: 12px 16px; border-radius: 6px; font-size: 13px; background: rgba(23, 162, 184, 0.15); border: 1px solid #17a2b8;'
					}, [
						E('strong', { 'style': 'color: #17a2b8;' }, _('✔ У вас актуальная версия: ')),
						E('span', {}, 'v' + state.updateInfo.local_version + ' (' + _('на GitHub: ') + 'v' + state.updateInfo.remote_version + ')')
					]);
				}
			}

			var buttons = E('div', { 'class': 'cbi-page-actions', 'style': 'margin-top: 25px; display: flex; flex-wrap: wrap; gap: 10px;' }, [
				E('button', {
					'class': 'cbi-button cbi-button-action',
					'style': 'height: 38px; padding: 0 16px;',
					'disabled': state.benchLoading ? 'disabled' : null,
					'click': function() { actions.runBenchmark(); }
				}, state.benchLoading ? _('Идет тестирование (10 пакетов)...') : (state.benchmark ? _('Запустить повторный замер') : _('Запустить замер задержек (10 пакетов)'))),

				E('button', {
					'class': 'cbi-button cbi-button-save',
					'style': 'height: 38px; padding: 0 20px; font-weight: bold;',
					'click': function() { actions.applyAll(); }
				}, _('Применить всё сразу')),

				E('button', {
					'class': 'cbi-button cbi-button-reset',
					'style': 'height: 38px; padding: 0 16px;',
					'click': function() { actions.restoreBackup(); }
				}, _('Откатить к бэкапу')),

				E('button', {
					'class': 'cbi-button cbi-button-link',
					'style': 'height: 38px; padding: 0 12px;',
					'click': function() { actions.checkUpdate(); }
				}, _('Обновить плагин'))
			]);

			var sectionChildren = [
				E('h3', {}, _('Настройка и применение')),
				E('div', { 'class': 'cbi-map-descr' },
					_('Каждую настройку можно сохранить по отдельности или применить всё вместе одной кнопкой.')
				),
				grid
			];
			if (updateBanner) sectionChildren.push(updateBanner);
			sectionChildren.push(buttons);

			return E('div', { 'class': 'cbi-section' }, sectionChildren);
		}

		// =========================================================================
		// 4. Root Render Loop (State -> Pure Declarative Tree)
		// =========================================================================
		var container = E('div', { 'class': 'cbi-map' });

		function render() {
			while (container.firstChild) {
				container.removeChild(container.firstChild);
			}

			var components = [
				HeaderComponent(),
				StatusCardComponent(),
				RecommendationsComponent(),
				BenchmarkTableComponent(),
				CustomDnsComponent(),
				ConfigSectionComponent()
			];

			components.forEach(function(comp) {
				if (comp) container.appendChild(comp);
			});
		}

		render();
		return container;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
