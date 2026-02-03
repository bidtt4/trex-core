import ipaddress
from .trex_astf_exceptions import ASTFErrorWrongType, ASTFErrorMissingParam, ASTFErrorBadIp, ASTFErrorBadIpRange,ASTFErrorBadMac


class ArgVerify(object):

    @staticmethod
    def verify_mac(mac):
        array=mac.split(':');
        if len(array) !=6:
            return False
        for i, obj in enumerate(array):
            try:
               a=int("0x"+obj,16)
               if i == 0 and a & 1:
                   return False  # reserved for multicast / broadcast
            except Exception as e:
                return False
            if a>255:
                return False
        return True                

    @staticmethod
    def verify_ipv6(ip):
        try:
            return ipaddress.IPv6Address(ip)
        except ipaddress.AddressValueError:
            return None

    @staticmethod
    def verify_ipv4(ip):
        try:
            return ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return None

    @staticmethod
    def verify_ip(ip):
        try:
            return ipaddress.ip_address(ip)
        except ValueError:
            return None

    @staticmethod
    def verify_ipv4_range(ip_range):
        if len(ip_range) != 2:
            return False, "Range should contain two IPs"
        first_ip = ArgVerify.verify_ipv4(ip_range[0])
        if not first_ip:
            return False, "Bad first IP"
        second_ip = ArgVerify.verify_ipv4(ip_range[1])
        if not second_ip:
            return False, "Bad second IP"
        if first_ip > second_ip:
            return False, "Min IP is bigger than Max IP"
        return True, ""

    @staticmethod
    def verify_ip_range(ip_range):
        if len(ip_range) != 2:
            return False, "Range should contain two IPs"
        first_ip = ArgVerify.verify_ip(ip_range[0])
        if not first_ip:
            return False, "Bad first IP"
        second_ip = ArgVerify.verify_ip(ip_range[1])
        if not second_ip:
            return False, "Bad second IP"
        if first_ip.version != second_ip.version:
            return False, "IPs have different version"
        if first_ip > second_ip:
            return False, "Min IP is bigger than Max IP"
        return True, ""

    @staticmethod
    def verify(f_name, d):
        arg_types = d["types"]
        for arg in arg_types:
            name = arg["name"]
            given_arg = arg["arg"]
            if isinstance(arg["t"], list):
                needed_type = arg["t"]
            else:
                needed_type = [arg["t"]]
            if "allow_list" in arg:
                allow_list = arg["allow_list"]
            else:
                allow_list = False
            if "must" in arg:
                must = arg["must"]
            else:
                must = True
            if given_arg is None:
                if must:
                    raise ASTFErrorMissingParam(f_name, name)
                else:
                    continue
            if allow_list and (isinstance(given_arg, list) or isinstance(given_arg, tuple)):
                given_arg = given_arg[0]
            type_ok = False
            for one_type in needed_type:
                if one_type == "ip address":
                    if ArgVerify.verify_ipv4(given_arg):
                        type_ok = True
                    else:
                        raise ASTFErrorBadIp(f_name, name, given_arg)
                elif one_type == "ipv6_addr":
                  if ArgVerify.verify_ipv6(given_arg):
                     type_ok = True
                  else:
                      raise ASTFErrorBadIp(f_name, name, given_arg)
                elif one_type == "ipv4v6 address":
                  if ArgVerify.verify_ip(given_arg):
                     type_ok = True
                  else:
                      raise ASTFErrorBadIp(f_name, name, given_arg)
                elif one_type == "ip range":
                    ret, msg = ArgVerify.verify_ipv4_range(given_arg)
                    if ret:
                        type_ok = True
                    else:
                        raise ASTFErrorBadIpRange(f_name, name, given_arg, msg)
                elif one_type == "ipv4v6 range":
                    ret, msg = ArgVerify.verify_ip_range(given_arg)
                    if ret:
                        type_ok = True
                    else:
                        raise ASTFErrorBadIpRange(f_name, name, given_arg, msg)
                elif one_type == "mac":
                    if ArgVerify.verify_mac(given_arg):
                        type_ok = True
                    else:
                        raise ASTFErrorBadMac(f_name, name, given_arg)
                else:
                    if isinstance(given_arg, one_type):
                        type_ok = True
            if not type_ok:
                raise ASTFErrorWrongType(f_name, name, needed_type, allow_list)
