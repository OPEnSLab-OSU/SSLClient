# Python SSL certificate conversion tool.
# Download and converts SSL certs from PEM format into a C header that can be
# referenced from a sketch to load the certificate data (in binary DER format).
# Modified by the OPEnS lab to output certificate data in a format supported by
# BearSSL. 
# Author: Tony DiCola, Modified by Noah Koontz
#
# Dependencies:
#   click - Install with 'sudo pip install click' (omit sudo on windows)
#   PyOpenSSL - See homepage: https://pyopenssl.readthedocs.org/en/latest/
#               Should just be a 'sudo pip install pyopenssl' command, HOWEVER
#               on Windows you probably need a precompiled binary version.  Try
#               installing with pip and if you see errors when running that
#               OpenSSL can't be found then try installing egenix's prebuilt
#               PyOpenSSL library and OpenSSL lib:
#                 http://www.egenix.com/products/python/pyOpenSSL/
#
import cert_util
import click
import certifi

# Default name for the cert length varible
CERT_LENGTH_NAME = "TAs_NUM"
# Defualt name for the cert array varible
CERT_ARRAY_NAME = "TAs"

# Click setup and commands:
@click.group()
def pycert_bearssl():
    """OPEnS Python Certificate Tool
    This is a tool to download and convert SSL certificates and certificate
    chains into a C header format that can be imported into BearSSL
    """
    pass

@pycert_bearssl.command(short_help='Download SSL certs and save as a C header.')
@click.option('--port', '-p', type=click.INT, default=443,
              help='port to use for reading certificate (default 443, SSL)')
@click.option('--cert-var', '-c', default=CERT_ARRAY_NAME,
              help='name of the variable in the header which will contain certificate data (default: {0})'.format(CERT_ARRAY_NAME))
@click.option('--cert-length-var', '-l', default=CERT_LENGTH_NAME,
              help='name of the define in the header which will contain the length of the certificate data (default: {0})'.format(CERT_LENGTH_NAME))
@click.option('--output', '-o', type=click.File('w'), default='certificates.h',
              help='name of the output file (default: certificates.h)')
@click.option('--use-store', '-s', type=click.File('r'), default=certifi.where(),
              help='the location of the .pem file containing a list of trusted root certificates (default: use certifi.where())')
@click.option('--keep-dupes', '-d', is_flag=True, default=False,
              help='write all certs including any duplicates across domains (default: remove duplicates)')
@click.argument('domain', nargs=-1)
def download(port, cert_var, cert_length_var, output, use_store, keep_dupes, domain):
    """Download the SSL certificates for specified domain(s) and save them as a C
    header file that can be imported into a sketch.
    Provide at least one argument that is the domain to query for its SSL
    certificate, for example google.com for Google's SSL certificate.  You can
    provide any number of domains as additional arguments.  All of the certificates
    will be combined into a single output header.
    By default the file 'certificates.h' will be created, however you can change
    the name of the file with the --output option.
    If a chain of certificates is retrieved then only the root certificate (i.e.
    the last in the chain) will be saved.  However you can override this and
    force the full chain to be saved with the --full-chain option.
    Example of downloading google.com's SSL certificate and storing it in
    certificates.h:
      pycert download google.com
    Example of downloading google.com and adafruit.com's SSL certificates and
    storing them in data.h:
      pycert download --output data.h google.com adafruit.com
    Note that the certificates will be validated before they are downloaded!
    """
    # prepare the root certificate store
    cert_obj_store = cert_util.parse_root_certificate_store(use_store)
    cert_dict = dict([(cert.get_subject().hash(), cert) for cert in cert_obj_store])
    # Download the cert object for each provided domain.
    down_certs = []
    for d in domain:
        # Download the certificate (unfortunately python will _always_ try to
        # validate it so we have no control over turning that off).
        cert = cert_util.get_server_root_cert(d, port, cert_dict)
        if cert is None:
            raise click.ClickException('Could not download and/or validate the certificate for {0} port {1}!'.format(d, port))
        click.echo('Retrieved certificate for {0}'.format(d))
        # append cert to array
        down_certs.append(cert)
    # Combine PEMs and write output header.
    cert_util.x509_to_header(down_certs, cert_var, cert_length_var, output, keep_dupes)


@pycert_bearssl.command(short_help='Convert PEM certs into a C header.')
@click.option('--cert-var', '-c', default=CERT_ARRAY_NAME,
              help='name of the variable in the header which will contain certificate data (default: {0})'.format(CERT_ARRAY_NAME))
@click.option('--cert-length-var', '-l', default=CERT_LENGTH_NAME,
              help='name of the define in the header which will contain the length of the certificate data (default: {0})'.format(CERT_LENGTH_NAME))
@click.option('--output', '-o', type=click.File('w'), default='certificates.h',
              help='name of the output file (default: certificates.h)')
@click.option('--full-chain', '-f', is_flag=True, default=False,
              help='use the full certificate chain and not just the root/last cert (default: false, root cert only)')
@click.option('--keep-dupes', '-d', is_flag=True, default=False,
              help='write all certs including any duplicates (default: remove duplicates)')
@click.argument('cert', type=click.File('r'), nargs=-1)
def convert(cert_var, cert_length_var, output, full_chain, keep_dupes, cert):
    """Convert PEM certificates into a C header that can be imported into a
    sketch.  Specify each certificate to encode as a separate argument (each
    must be in PEM format) and they will be merged into a single file.
    By default the file 'certificates.h' will be created, however you can change
    the name of the file with the --output option.
    If a chain of certificates is found then only the root certificate (i.e.
    the last in the chain) will be saved.  However you can override this and
    force the full chain to be saved with the --full-chain option.
    Example of converting a foo.pem certificate into a certificates.h header:
      pycert convert foo.pem
    Example of converting foo.pem and bar.pem certificates into data.h:
      pycert convert foo.pem bar.pem
    """
    # Load all the provided PEM files.
    pems = []
    for c in cert:
        cert_pem = c.read()
        click.echo('Loaded certificate {0}'.format(c.name))
        pems.append(cert_pem)
    # Combine PEMs and write output header.
    PEM_to_header(pems, cert_var, cert_length_var, output, full_chain, keep_dupes)


if __name__ == '__main__':
    pycert_bearssl()