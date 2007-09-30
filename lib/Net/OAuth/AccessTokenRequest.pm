package Net::OAuth::AccessTokenRequest;
use warnings;
use strict;
use base 'Net::OAuth::Request';

__PACKAGE__->add_required_request_params(qw/token/);
__PACKAGE__->add_required_api_params(qw/token_secret/);
__PACKAGE__->add_to_signature(qw/token_secret/);
sub allow_extra_params {0}

=head1 NAME

Net::OAuth::RequestTokenRequest - An OAuth protocol request for an Access Token

=head1 SEE ALSO

L<Net::OAuth::Request>, L<http://oauth.net>

=head1 AUTHOR

Keith Grennan, C<< <kgrennan at cpan.org> >>

=head1 COPYRIGHT & LICENSE

Copyright 2007 Keith Grennan, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;