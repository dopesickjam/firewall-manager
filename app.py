from fabric import Connection
from datetime import datetime, timezone, timedelta
import logging, argparse, sys, yaml, invoke
from yaml.loader import SafeLoader
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

ips_yaml_path = 'templates/servers.yaml'
groups_yaml_path = 'templates/groups.yaml'

parser = argparse.ArgumentParser(description='')
parser.add_argument('--config', dest='ufw_rules', help='path to ufw yaml rules', nargs=1, metavar=("FILE"))
parser.add_argument('--flush', dest='flush', help='flush firewall before apply new rules', action="store_true")
parser.add_argument('--flush_iptables', dest='flush_iptables', help='flush iptables!!! there is a risk of losing the connection', action="store_true")
parser.add_argument('--remove', dest='remove', help='remove rule or ip', type=str)
args = parser.parse_args()

def read_yaml(config):
    with open(config) as f:
        return yaml.load(f, Loader=SafeLoader)

def check_ufw(c):
    try:
        c.sudo('ufw --version')
        logging.info(f'ufw installed for this server: {target_server_ip}')
    except invoke.exceptions.UnexpectedExit:
        logging.info(f'ufw not installed for this server: {target_server_ip}')
        c.sudo('apt-get install ufw -y')

def ufw_reset(c):
    c.sudo('ufw --force disable')
    c.sudo('ufw --force reset')
    logging.info(f'firewall was flushed for this server: {target_server_ip}')

def iptables_reset(c):
    c.sudo('iptables -F')
    c.sudo('ip6tables -F')
    logging.info(f'iptables was flushed for this server: {target_server_ip}')

def ufw_enable(c):
    c.sudo('ufw --force enable')

def ufw_add(c, ip, proto, port, comment, rule_type):
    if port == 'any':
        logging.info(f'ufw {rule_type} from {ip} comment "{comment}"')
        c.sudo(f'ufw {rule_type} from {ip} comment "{comment}"')
    elif ip == 'any':
        logging.info(f'ufw {rule_type} proto {proto} to any port {port} comment "{comment}"')
        c.sudo(f'ufw {rule_type} proto {proto} to any port {port} comment "{comment}"')
    else:
        for item in port.split(','):
            logging.info(f'ufw {rule_type} from {ip} proto {proto} to any port {item} comment "{comment}"')
            c.sudo(f'ufw {rule_type} from {ip} proto {proto} to any port {port} comment "{comment}"')

def ufw_remove(c, remove_rule):
    for remove in remove_rule.split(','):
        while True:
            line = c.sudo(f'ufw status numbered | grep {remove} |sed "1!d"')
            if line.stdout:
                start = line.stdout.find('[')
                end = line.stdout.find(']')
                number = line.stdout[start+1:end].strip()
                logging.info(f'find rule with number: {number}')
                c.sudo(f'ufw --force delete {number}')
            else:
                logging.info(f'{target_server_ip} clean from rule: {remove}')
                break

def get_ip(global_name, group, name):
    return ips_yaml[global_name][group][name]

ips_yaml = read_yaml(ips_yaml_path)
groups_yaml = read_yaml(groups_yaml_path)

logging.info(f'Render config from {args.ufw_rules[0]}')
server_rules = read_yaml(args.ufw_rules[0])

if server_rules['ufw_simple']['enabled']:
    server_path = server_rules['ufw_simple']['host'].split('.')

    target_server_ip = get_ip(server_path[0],server_path[1],server_path[2])
    target_server_user = server_rules['ufw_simple']['user_ssh']
    target_server_port = server_rules['ufw_simple']['port_ssh']

    c = Connection(host=target_server_ip, user=target_server_user, port=target_server_port)

    check_ufw(c)

    if args.flush:
        ufw_reset(c)

    if args.flush_iptables:
        iptables_reset(c)

    if args.remove:
        ufw_remove(c, args.remove)

    allow_groups = server_rules['ufw_simple']['allow']

    for allow_group in allow_groups:
        for group in groups_yaml['groups']:
            if group['name'] == allow_group:
                protocol = group['proto']
                ports = str(group['ports']).split(',')
                allowed_servers = group['ips']

                for port in ports:
                    if allowed_servers == 'any':
                        ufw_add(c, 'any', protocol, port, 'world', 'allow')
                    else:
                        for ip in allowed_servers:
                            ip = ip.split('.')
                            server_ip = get_ip(ip[0], ip[1], ip[2])
                            ufw_add(c, server_ip, protocol, port, ip[2], 'allow')

    ufw_enable(c)
else:
    logging.info(f'ufw disable for {args.ufw_rules[0]}')