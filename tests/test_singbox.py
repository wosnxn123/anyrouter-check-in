"""utils/singbox.py：Xray 分享链接 -> sing-box 配置。"""

import base64
import json

import pytest

from utils.singbox import build_config, mask_link, parse_share_link, parse_share_links

VLESS_REALITY = (
	'vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443'
	'?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome'
	'&pbk=PUBLIC_KEY_XYZ&sid=abcd1234&type=tcp&flow=xtls-rprx-vision#%E8%8A%82%E7%82%B9A'
)
VLESS_WS = (
	'vless://uuid-ws@node.example.com:8443?type=ws&security=tls&path=%2Fws-path'
	'&host=cdn.example.com&sni=sni.example.com&allowInsecure=1&ed=2048#WS%E8%8A%82%E7%82%B9'
)
TROJAN = 'trojan://pass%40word@t.example.com:443?sni=t.example.com&type=grpc&serviceName=svc&allowInsecure=1#trojan'
SS_BASE64 = 'ss://{}@1.1.1.1:8388#ss%E8%8A%82%E7%82%B9'.format(
	base64.urlsafe_b64encode(b'aes-256-gcm:secret-password').decode()
)
SS_PLAIN = 'ss://chacha20-ietf-poly1305:plain-pass@2.2.2.2:8389#ss-plain'
SS_PLUGIN = 'ss://{}@3.3.3.3:8390?plugin=obfs-local%3Bobfs%3Dhttp#ss-plugin'.format(
	base64.urlsafe_b64encode(b'aes-128-gcm:pw').decode()
)
HY2 = 'hy2://user:pass@h2.example.com:443?sni=h2.example.com&insecure=1&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=100#hy2'
HYSTERIA2_ALIAS = 'hysteria2://pw2@h2b.example.com:8443?obfs=none#hy2-alias'


def _vmess_link(payload: dict, remark: str = 'vmess节点') -> str:
	encoded = base64.b64encode(json.dumps(payload).encode()).decode()
	return f'vmess://{encoded}#{remark}'


VMESS_PAYLOAD = {
	'v': '2',
	'ps': 'vmess节点',
	'add': 'a.b.c.d',
	'port': '8443',
	'id': 'vmess-uuid',
	'aid': '2',
	'scy': 'aes-128-gcm',
	'net': 'ws',
	'type': 'none',
	'host': 'h.example.com',
	'path': '/vm',
	'tls': 'tls',
	'sni': 'sni.example.com',
	'fp': 'chrome',
}


def test_parse_vless_reality():
	remark, outbound = parse_share_link(VLESS_REALITY)

	assert remark == '节点A'
	assert outbound['type'] == 'vless'
	assert outbound['server'] == '1.2.3.4'
	assert outbound['server_port'] == 443
	assert outbound['uuid'] == '11111111-2222-3333-4444-555555555555'
	assert outbound['flow'] == 'xtls-rprx-vision'
	# tcp 传输不需要 transport 字段
	assert 'transport' not in outbound
	assert outbound['tls']['enabled'] is True
	assert outbound['tls']['server_name'] == 'www.microsoft.com'
	assert outbound['tls']['utls'] == {'enabled': True, 'fingerprint': 'chrome'}
	assert outbound['tls']['reality'] == {
		'enabled': True,
		'public_key': 'PUBLIC_KEY_XYZ',
		'short_id': 'abcd1234',
	}


def test_parse_vless_ws_with_early_data():
	_, outbound = parse_share_link(VLESS_WS)

	assert outbound['tls']['insecure'] is True
	assert outbound['tls']['server_name'] == 'sni.example.com'
	assert outbound['transport'] == {
		'type': 'ws',
		'path': '/ws-path',
		'headers': {'Host': 'cdn.example.com'},
		'max_early_data': 2048,
		'early_data_header_name': 'Sec-WebSocket-Protocol',
	}


def test_parse_vless_plaintext_has_no_tls():
	link = 'vless://plain-uuid@p.example.com:2095?type=ws&path=%2F&security=none#plain'
	_, outbound = parse_share_link(link)

	assert 'tls' not in outbound
	assert outbound['transport']['type'] == 'ws'


def test_parse_vless_infers_tls_from_sni_when_security_missing():
	link = 'vless://uuid@i.example.com:443?sni=i.example.com#inferred'
	_, outbound = parse_share_link(link)

	assert outbound['tls']['enabled'] is True
	assert outbound['tls']['server_name'] == 'i.example.com'


def test_parse_vless_ignores_unsupported_flow_and_fingerprint(capsys):
	link = 'vless://uuid@f.example.com:443?security=tls&flow=xtls-rprx-direct&fp=weird#bad'
	_, outbound = parse_share_link(link)

	assert 'flow' not in outbound
	assert 'utls' not in outbound['tls']
	assert '忽略不支持的 flow' in capsys.readouterr().err


def test_parse_vless_rejects_missing_port():
	assert parse_share_link('vless://uuid@1.2.3.4#noport') is None


def test_parse_vmess():
	_, outbound = parse_share_link(_vmess_link(VMESS_PAYLOAD))

	assert outbound['type'] == 'vmess'
	assert outbound['server'] == 'a.b.c.d'
	assert outbound['server_port'] == 8443
	assert outbound['uuid'] == 'vmess-uuid'
	assert outbound['security'] == 'aes-128-gcm'
	assert outbound['alter_id'] == 2
	assert outbound['transport'] == {'type': 'ws', 'path': '/vm', 'headers': {'Host': 'h.example.com'}}
	assert outbound['tls']['server_name'] == 'sni.example.com'
	assert outbound['tls']['utls']['fingerprint'] == 'chrome'


def test_parse_vmess_port_as_int_and_zero_alter_id():
	payload = dict(VMESS_PAYLOAD, port=443, aid=0, scy='zero', tls='', net='tcp')
	_, outbound = parse_share_link(_vmess_link(payload))

	assert outbound['server_port'] == 443
	assert 'alter_id' not in outbound
	assert outbound['security'] == 'none'
	assert 'tls' not in outbound
	assert 'transport' not in outbound


def test_parse_vmess_tcp_http_header_becomes_http_transport():
	payload = dict(VMESS_PAYLOAD, net='tcp', type='http', tls='')
	_, outbound = parse_share_link(_vmess_link(payload))

	assert outbound['transport']['type'] == 'http'
	assert outbound['transport']['method'] == 'PUT'


def test_parse_vmess_grpc_falls_back_to_path_as_service_name():
	payload = dict(VMESS_PAYLOAD, net='grpc', serviceName='', path='/svc-name', tls='')
	_, outbound = parse_share_link(_vmess_link(payload))

	assert outbound['transport'] == {'type': 'grpc', 'service_name': 'svc-name'}


def test_parse_vmess_rejects_bad_base64_and_bad_json():
	assert parse_share_link('vmess://!!!not-base64!!!') is None
	encoded = base64.b64encode(b'not json at all').decode()
	assert parse_share_link(f'vmess://{encoded}') is None
	encoded_list = base64.b64encode(b'[1,2,3]').decode()
	assert parse_share_link(f'vmess://{encoded_list}') is None


def test_parse_vmess_rejects_missing_fields():
	assert parse_share_link(_vmess_link({'add': 'a.b.c.d', 'port': '443'})) is None


def test_parse_trojan_decodes_password_and_grpc():
	remark, outbound = parse_share_link(TROJAN)

	assert remark == 'trojan'
	assert outbound['type'] == 'trojan'
	assert outbound['server'] == 't.example.com'
	assert outbound['server_port'] == 443
	assert outbound['password'] == 'pass@word'
	assert outbound['transport'] == {'type': 'grpc', 'service_name': 'svc'}
	# Trojan 必须 TLS，所以 tls 字段总是存在
	assert outbound['tls']['enabled'] is True
	assert outbound['tls']['insecure'] is True


def test_parse_trojan_falls_back_to_host_as_sni():
	link = 'trojan://pw@h.example.com:443?host=h.example.com#no-sni'
	_, outbound = parse_share_link(link)

	assert outbound['tls']['server_name'] == 'h.example.com'


def test_parse_trojan_does_not_use_ip_host_as_sni():
	link = 'trojan://pw@5.6.7.8:443?host=5.6.7.8#ip-sni'
	_, outbound = parse_share_link(link)

	assert 'server_name' not in outbound['tls']


def test_parse_shadowsocks_base64_form():
	remark, outbound = parse_share_link(SS_BASE64)

	assert remark == 'ss节点'
	assert outbound == {
		'type': 'shadowsocks',
		'server': '1.1.1.1',
		'server_port': 8388,
		'method': 'aes-256-gcm',
		'password': 'secret-password',
	}


def test_parse_shadowsocks_plain_form():
	_, outbound = parse_share_link(SS_PLAIN)

	assert outbound['method'] == 'chacha20-ietf-poly1305'
	assert outbound['password'] == 'plain-pass'


def test_parse_shadowsocks_2022_method_keeps_base64_password():
	key = base64.b64encode(b'0' * 32).decode()
	userinfo = base64.urlsafe_b64encode(f'2022-blake3-aes-256-gcm:{key}'.encode()).decode()
	_, outbound = parse_share_link(f'ss://{userinfo}@9.9.9.9:443#ss2022')

	assert outbound['method'] == '2022-blake3-aes-256-gcm'
	assert outbound['password'] == key


def test_parse_shadowsocks_skips_plugin_node(capsys):
	assert parse_share_link(SS_PLUGIN) is None
	assert '插件节点暂不支持' in capsys.readouterr().err


def test_parse_shadowsocks_rejects_unparsable_userinfo():
	assert parse_share_link('ss://notbase64!!@1.1.1.1:8388#bad') is None


def test_parse_hysteria2():
	remark, outbound = parse_share_link(HY2)

	assert remark == 'hy2'
	assert outbound == {
		'type': 'hysteria2',
		'server': 'h2.example.com',
		'server_port': 443,
		'password': 'user:pass',
		'up_mbps': 50,
		'down_mbps': 100,
		'obfs': {'type': 'salamander', 'password': 'obfspw'},
		'tls': {'enabled': True, 'server_name': 'h2.example.com', 'insecure': True},
	}


def test_parse_hysteria2_scheme_alias_without_obfs():
	_, outbound = parse_share_link(HYSTERIA2_ALIAS)

	assert outbound['type'] == 'hysteria2'
	assert 'obfs' not in outbound
	assert 'up_mbps' not in outbound
	assert outbound['tls'] == {'enabled': True, 'server_name': 'h2b.example.com'}


def test_parse_hysteria2_rejects_missing_password():
	assert parse_share_link('hy2://h2.example.com:443#nopw') is None


def test_unsupported_scheme_returns_none(capsys):
	assert parse_share_link('http://127.0.0.1:1080') is None
	assert '不支持的协议 http' in capsys.readouterr().err


def test_link_without_scheme_returns_none():
	assert parse_share_link('just-some-text') is None


def test_parse_share_links_handles_multiple_lines_and_skips_junk():
	raw = '\n'.join(
		[
			'',
			'   ',
			'# 这是注释行',
			VLESS_REALITY,
			'not-a-link',
			'http://127.0.0.1:1080',
			TROJAN,
			SS_BASE64,
			HY2,
			_vmess_link(VMESS_PAYLOAD),
		]
	)

	nodes = parse_share_links(raw)

	assert [tag for tag, _ in nodes] == ['节点A', 'trojan', 'ss节点', 'hy2', 'vmess节点']
	assert [outbound['type'] for _, outbound in nodes] == ['vless', 'trojan', 'shadowsocks', 'hysteria2', 'vmess']


def test_parse_share_links_deduplicates_tags():
	nodes = parse_share_links(f'{TROJAN}\n{TROJAN}\n{TROJAN}')

	assert [tag for tag, _ in nodes] == ['trojan', 'trojan #2', 'trojan #3']


def test_parse_share_links_falls_back_to_server_when_no_remark():
	nodes = parse_share_links('trojan://pw@t.example.com:443?sni=t.example.com')

	assert nodes[0][0] == 't.example.com'


def test_parse_share_links_returns_empty_for_blank_input():
	assert parse_share_links('') == []


def test_build_config_wires_group_and_inbound():
	nodes = parse_share_links(f'{VLESS_REALITY}\n{TROJAN}')

	config = build_config(nodes, port=7891, test_url='https://example.com/204', group_tag='CHECKIN')

	assert config['log'] == {'level': 'warn', 'timestamp': True}
	assert config['inbounds'] == [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7891}]
	assert config['route'] == {'final': 'CHECKIN'}

	group = config['outbounds'][-1]
	assert group['type'] == 'urltest'
	assert group['tag'] == 'CHECKIN'
	assert group['outbounds'] == ['节点A', 'trojan']
	assert group['url'] == 'https://example.com/204'
	assert group['interval'] == '3m'
	assert group['tolerance'] == 150

	first = config['outbounds'][0]
	assert first['type'] == 'vless'
	assert first['tag'] == '节点A'
	# 每个出站都必须有唯一 tag，否则 sing-box check 会失败
	tags = [outbound['tag'] for outbound in config['outbounds']]
	assert len(tags) == len(set(tags))


def test_build_config_rejects_empty_nodes():
	with pytest.raises(ValueError, match='没有解析出任何可用的代理节点'):
		build_config([])


def test_mask_link_hides_credentials(capsys):
	assert mask_link(VLESS_REALITY) == 'vless://***@1.2.3.4:443'
	assert mask_link(SS_BASE64) == 'ss://***@1.1.1.1:8388'
	assert mask_link('not-a-link') == '<不是合法的分享链接>'

	parse_share_link('vless://super-secret-uuid@1.2.3.4:443#x')
	parse_share_link('trojan://hunter2@t.example.com:443?sni=a#x')

	# 解析失败的告警里不能出现密码
	assert parse_share_link('ss://!!!!@1.1.1.1:8388#x') is None
	err = capsys.readouterr().err
	assert 'super-secret-uuid' not in err
	assert 'hunter2' not in err
