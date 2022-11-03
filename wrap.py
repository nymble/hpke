#!/usr/bin/env python3
""" wrap.py
    A command-line tool.
"""
version = '0.01'
from persona import Persona
from cipher_suite import supported_cipher_suites, HPKE_Curve25519_ChaCha20Poly1305
import click # for commandline interface
import sys

cipher_suite_name_list = [ Cs.__name__      for Cs in supported_cipher_suites ]
cipher_suite_name_dict = { Cs.__name__ : Cs for Cs in supported_cipher_suites }
DEFAULT_CIPHER_SUITE_NAME = HPKE_Curve25519_ChaCha20Poly1305.__name__
encoding_name_list = ['hex','bin']


# --- 'click' based command-line interface ------------------------------------
# Definition of context for options before the command
# for colors available see:
#     https://github.com/pallets/click/blob/main/examples/colors/colors.py
global              NORMAL,  ERROR, HIGHLIGHT, HIGHLIGHT2,     OTHER,   ALERT
color_sets = {'d': ['green', 'red', 'yellow', 'bright_yellow', 'cyan', 'magenta'],   # dark mode
              'l': ['green', 'red', 'blue',   'bright_blue',   'cyan', 'magenta' ]}  # light mode
# Setup initial context for any command
@click.version_option(version)
@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--verbosity', '-v', type=int, default=1, help='Verbocity 0 (silent) to 3 (debug)')
@click.option('--color', '-c',
               type=click.Choice(['l', 'd']), default='l',
               help='Color set to support light and dark themes')
@click.pass_context     # ctx
def cli(ctx, verbosity, color):
    """ A suite of command-line commands.
    """
    context.verbocity = verbocity
    NORMAL, ERROR, SKIP, DRYRUN, OTHER, EXECUTE = color_sets[color]
    try:
        pass
    except Exception as e:
        click.secho( f"ERROR: {e}", fg=ERROR)
        sys.exit(1)
    else:
        ctx.obj = stuff # all subsequent 'click' commands use instance

@click.pass_obj # uses context from command to
def log( context, level, text, fg=None, nl=True ):
    """ Display log messages based on verbosity level """
    if level <= context.verbosity:
        click.secho( text, fg=fg, nl=nl)

@cli.command() #---------------------------------------------------------------
@click.option('--cipher_suite', '-c', 'cipher_suite_name',
              default=DEFAULT_CIPHER_SUITE_NAME,
              type=click.Choice( cipher_suite_name_list ),
              help=f"Specify cipher suite (default={DEFAULT_CIPHER_SUITE_NAME})")
@click.option('--encoding', '-e', default='hex',
              type=click.Choice( encoding_name_list ),
              help="Select encoding format for output")
@click.option('--input_file', '-i',
              type=click.File('rb'),
              default=sys.stdin,
              help="Input file, default STDIN")
@click.option('--output_file', '-o',
              default='-',
              type=click.File('wb'),
              help="Output file, default SDOUT")
def wrap(cipher_suite_name, key,authenticated, input_file, output_file):
    """ Wrap a file using selected cipher suite.
    """
    plain_text = input_file.read() # binary/bytes file read
    cipher_text = plain_text # stubbed
    output_file.write( cipher_text ) # expects bytes for binary write


@cli.command() #---------------------------------------------------------------
@click.option('--cipher_suite', '-c', 'cipher_suite_name', default=DEFAULT_CIPHER_SUITE_NAME, type=click.Choice( cipher_suite_name_list ) )
@click.password_option('--key', '-k')
@click.argument('input_file', type=click.File('rb'))
@click.argument('output_file', type=click.File('wb'))
def unwrap(cipher_suite_name, key, input_file, output_file):
    """ Unwrap a file using selected cipher suite.
    """
    Cs = cipher_suites_by_name[ cipher_suite_name ] # instantiate class from dictionary

    cipher_text = input_file.read()
    plain_text = cipher_text
    output_file.write( plain_text )

@cli.command() #---------------------------------------------------------------
def suites():
    """ List the available cipher suites that may be invoked with the -c option.
    """
    click.echo( f"The following {len(supported_cipher_suites)} cipher suites are supported:")
    for Cs in supported_cipher_suites:
        base_class_name = Cs.__name__.replace("_", " ")
        click.echo( "    {} - {}".format( Cs.csi.hex(), Cs.__name__))

if __name__ == '__main__':
    cli()
