import ipaddress
from datetime import datetime, timedelta
from cryptography import  x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import  hashes, serialization
from cryptography.hazmat.backends import  default_backend
from cryptography.hazmat.primitives.asymmetric  import rsa
import ipaddress

server_IP = '136.243.184.227'
h_name = 'Juventus Official Fan Club Iran'

#keep free space ot the block ans define the kesy size

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

#set the name of the certificate

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, h_name)
])

#add IP address for some browsers

alt_names = [x509.DNSName(h_name)]
alt_names.append(x509.DNSName(server_IP))

#ignore Google Chrome errors
alt_names.append(x509.IPAddress(ipaddress.ip_address(server_IP)))

# creating the certificate, certificate authority is doing by ourselves
basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
now = datetime.utcnow()
cert = (
    x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(basic_contraints, True)
        .add_extension(x509.SubjectAlternativeName(alt_names), False)
        .sign(key, hashes.SHA256(), default_backend())
)

# encode our certificate

my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
my_key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

# write to the file

with open('myCertificate.crt', 'wb') as c:
    c.write(my_cert_pem)

with open('myCertificate.crt', 'wb') as c:
    c.write(my_key_pem)



