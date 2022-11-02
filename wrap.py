#!/usr/bin/env python3
""" wrap.py

    A command-line tool ... to be completed
    
"""
import click
from persona import Persona
from cipher_suite import supported_cipher_suites, HPKE_Curve25519_ChaCha20Poly1305

cipher_suite_name_list = [ Cs.__name__ for Cs in supported_cipher_suites]
cipher_suites_by_name = {Cs.__name__:Cs for Cs in supported_cipher_suites}

DEFAULT_CIPHER_SUITE_NAME = HPKE_Curve25519_ChaCha20Poly1305.__name__


#
# --- 'click' based command-line interface ------------------------------------
@click.version_option(0.4)

@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.pass_context     # ctx
def cli(ctx):
    """ A tool to wrap/unwrap a file using hybrid public key encryption. """

@cli.command()
@click.option('--cipher_suite', '-c', 'cipher_suite_name', default=DEFAULT_CIPHER_SUITE_NAME, type=click.Choice( cipher_suite_name_list ) )
@click.password_option('--key', '-k')
@click.option('--auth', 'authenticated', flag_value=True, default=True )
@click.option('--unauth', 'authenticated', flag_value=False )
@click.argument('input_file', type=click.File('rb'))
@click.argument('output_file', type=click.File('wb'))
def wrap(cipher_suite_name, key,authenticated, input_file, output_file):
    """ Wrap a file using selected cipher suite:
            wrap [OPTIONS] wrap <in_file> <out_file>
    """
    
    plain_text = input_file.read() # binary/bytes file read

    cipher_text = plain_text # stubbed

    output_file.write( cipher_text ) # expects bytes for binary write


@cli.command()
@click.option('--cipher_suite', '-c', 'cipher_suite_name', default=DEFAULT_CIPHER_SUITE_NAME, type=click.Choice( cipher_suite_name_list ) )
@click.password_option('--key', '-k')
@click.argument('input_file', type=click.File('rb'))
@click.argument('output_file', type=click.File('wb'))
def unwrap(cipher_suite_name, key, input_file, output_file):
    """ Unwrap a file using selected cipher suite:
            wrap unwrap [OPTIONS] <in_file> <out_file>
             -c   cipher suite
    """
    Cs = cipher_suites_by_name[ cipher_suite_name ] # instantiate class from dictionary

    cipher_text = input_file.read()

    output_file.write( cipher_text )


@cli.command()
def list():
    """ List the available cipher suites that may be invoked with the -c option.
    """
    click.echo( "The following {} cipher suites are supported:".format( len(supported_cipher_suites)))
    for Cs in supported_cipher_suites:
        base_class_name = Cs.__name__.replace("_", " ")
        click.echo( "    {} - {}".format( Cs.csi.hex(), Cs.__name__))


if __name__ == '__main__':
    cli()
