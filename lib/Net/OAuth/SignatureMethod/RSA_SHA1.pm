package Net::OAuth::SignatureMethod::RSA_SHA1;
use warnings;
use strict;
use Crypt::RSA::SS::PKCS1v15;

sub sign {
    my $self = shift;
    my $request = shift;
    my $pkcs = new Crypt::RSA::SS::PKCS1v15 (Digest => 'SHA1');
    my $signature = $pkcs->sign(
        Message => $request->signature_base_string,
        Key     => $request->signature_key,
    ) || die $pkcs->errstr;
    return $signature
}

sub verify {
    my $self = shift;
    my $request = shift;
    my $result = $pkcs->sign(
        Message => $request->signature_base_string,
        Key     => $request->signature_key,
        Signature => $request->signature,
    );
    die $pkcs->errstr if !$result and $pkcs->errstr ne 'Invalid signature.'
    return $result;
}

=head1 NAME

Net::OAuth::SignatureMethod::RSA_SHA1 - RSA_SHA1 Signature Method for OAuth protocol

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