import socket
from n6sdk.data_spec.fields import *

# taken from http://snipplr.com/view/43003/regex--match-ipv6-address/](http://snipplr.com/view/43003/regex--match-ipv6-address/
IPv6_STRICT_DECIMAL_REGEX = re.compile(r'''
^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$
''', re.VERBOSE)

class DirField(UnicodeEnumField):
    enum_values = ('src', 'dst')

class IPv6Field(UnicodeLimitedField, UnicodeRegexField):
    regex = IPv6_STRICT_DECIMAL_REGEX
    error_msg_template = '"{}" is not a valid IPv6 address'
    max_length = 45


class ExtendedAddressField(AddressField):
    key_to_subfield_factory = AddressField.key_to_subfield_factory.copy()
    key_to_subfield_factory.update(
        dir=DirField,
        ipv6=IPv6Field,
        rdns=UnicodeField,
    )
    required_keys = {'dir'}  # if no field is absolutely obligatory


class NotInUseExtendedAddressField(AddressField):
    AddressField.key_to_subfield_factory['dir'] = DirField
    AddressField.key_to_subfield_factory['ip6'] = IPv6Field
    AddressField.required_keys.add('dir')

def convert_conf(value):
    if value == 'LOW':
        return 'low'
    elif value == 'MED':
        return 'medium'
    elif value == 'HIGH':
        return 'high'

def is_ipv4(n):
    if n is '':
	return False
    try:
        socket.inet_pton(socket.AF_INET, n)
        return True
    except socket.error:
        return False

def is_ipv6(n):
    if n is '':
	return False
    try:
        socket.inet_pton(socket.AF_INET6, n)
        return True
    except socket.error:
        return False


def is_fqdn(n):
     if is_ipv4(n) is False and is_ipv6(n) is False:
	return True
     return False
