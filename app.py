from fabric import Connection
from datetime import datetime, timezone, timedelta
import logging, argparse, sys, yaml, invoke
from yaml.loader import SafeLoader
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

parser = argparse.ArgumentParser(description='')
parser.add_argument('--config', dest='ufw_rules', help='path to ufw yaml rules', nargs=1, metavar=("FILE"))
parser.add_argument('--flush', dest='flush', help='flush firewall before apply new rules', action="store_true")
parser.add_argument('--remove', dest='remove', help='remove rule or ip', type=str)
parser.add_argument('--servers_path', dest='servers_path', help='path to servers list', type=str)
args = parser.parse_args()

def read_yaml(config):
    with open(config) as f:
        return yaml.load(f, Loader=SafeLoader)

def check_ufw(c):
    try:
        c.sudo('ufw --version')
        logging.info(f'ufw installed for this server: {server_name}')
    except invoke.exceptions.UnexpectedExit:
        logging.info(f'ufw not installed for this server: {server_name}')
        c.sudo('apt-get install ufw -y')

def ufw_reset(c):
    c.sudo('ufw --force disable')
    c.sudo('ufw --force reset')
    c.sudo('iptables -F')
    c.sudo('ip6tables -F')
    logging.info(f'firewall was flushed for this server: {server_name}')

def ufw_enable(c):
    c.sudo('ufw --force enable')

def ufw_add(c, ip, proto, port, comment, rule_type):
    if port == 'any':
        logging.info(f'ufw {rule_type} from {ip} comment "{comment}"')
        c.sudo(f'ufw {rule_type} from {ip} comment "{comment}"')
    elif ip == 'any':
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
                logging.info(f'{server_name} clean from rule: {remove}')
                break

def get_variables(server_rules, rules_type, rule):
    port = server_rules['ufw_simple'][rule][rules_type]['to_port'] if 'to_port' in server_rules['ufw_simple'][rule][rules_type] else 'any'
    proto = server_rules['ufw_simple'][rule][rules_type]['proto'] if 'proto' in server_rules['ufw_simple'][rule][rules_type] else 'any'
    from_list = server_rules['ufw_simple'][rule][rules_type]['from'] if 'from' in server_rules['ufw_simple'][rule][rules_type] else 'any'

    return  port, proto, from_list


if args.ufw_rules:
    logging.info(f'Render config from {args.ufw_rules[0]}')

    server_rules = read_yaml(args.ufw_rules[0])

    all_servers = read_yaml(args.servers_path)

    server_name = server_rules['server']['name']
    server_user = server_rules['server']['user']
    server_port = server_rules['server']['port']
    c = Connection(host=server_name, user=server_user, port=server_port)

    ufw_status = server_rules['ufw_simple']['enabled']

    if ufw_status:
        check_ufw(c)

        if args.flush:
            ufw_reset(c)

        if args.remove:
            ufw_remove(c, args.remove)

        for allow_rules in server_rules['ufw_simple']['allow']:
            port, proto, from_list = get_variables(server_rules, allow_rules, 'allow')

            if from_list == 'any':
                ufw_add(c, 'any', proto, port, 'open for world', 'allow')

            for server in from_list:
                server = server.split('.')

                if len(server) == 2:
                    multi_rule = all_servers[server[0]][server[1]]
                    for rule in multi_rule:
                        ufw_add(c, multi_rule[rule], proto, port, rule, 'allow')
                if len(server) == 3:
                    single_rule = all_servers[server[0]][server[1]][server[2]]
                    ufw_add(c, single_rule, proto, port, server[2], 'allow')

        rules = server_rules['ufw_simple']['deny'] if 'deny' in server_rules['ufw_simple'] else 'any'
        if not 'any' in rules:
            for deny_rules in server_rules['ufw_simple']['deny']:
                port, proto, from_list = get_variables(server_rules, deny_rules, 'deny')

                for server in from_list:
                    server = server.split('.')

                    if len(server) == 2:
                        multi_rule = all_servers[server[0]][server[1]]
                        for rule in multi_rule:
                            ufw_add(c, multi_rule[rule], proto, port, rule, 'deny')
                    if len(server) == 3:
                        single_rule = all_servers[server[0]][server[1]][server[2]]
                        ufw_add(c, single_rule, proto, port, server[2], 'deny')

        ufw_enable(c)
                    
    else:
        logging.info(f'ufw disable for this server: {server_name}')