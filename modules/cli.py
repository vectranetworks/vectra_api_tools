import getpass

def commonArgs(parser):
    parser.add_argument('--url',
                        required=True,
                        help='IP or FQDN for Vectra brain (http://www.example.com)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--token',
                       help='api token')
    group.add_argument('--user',
                       help='username for basic auth')
    parser.add_argument('--page',
                        help='page number to when returnining multiple pages')
    parser.add_argument('--size',
                        dest='page_size',
                        help='number of results to return per page (default: %(default)s)',
                        default=5000)
    parser.add_argument('--state',
                        choices=['active', 'inactive'],
                        help='state of object (default: %(default)s)',
                        default='active')
    parser.add_argument('--fields',
                        help='fields to return')
    parser.add_argument('--order',
                        help='field to use for ordering')

    return parser


def getPassword():
    return getpass.getpass(prompt='Please enter password')
