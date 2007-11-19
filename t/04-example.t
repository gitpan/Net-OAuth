#!perl -T

use strict;
use warnings;
use Test::More tests => 5;
use LWP::UserAgent;

BEGIN {
    use_ok( 'Net::OAuth::Request' );
	use_ok( 'Net::OAuth::RequestTokenRequest' );
	use_ok( 'Net::OAuth::AccessTokenRequest' );
	use_ok( 'Net::OAuth::ProtectedResourceRequest' );
}

diag( "Testing Net::OAuth $Net::OAuth::Request::VERSION, Perl $], $^X" );


my $timestamp = time();
my $endpoint = 'http://term.ie/oauth/example/request_token.php';
my $request = Net::OAuth::RequestTokenRequest->new(
        consumer_key => 'key',
        consumer_secret => 'secret',
        request_url => $endpoint,
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => $timestamp,
        nonce => 'hsu94j3884jdopsl',
);

$request->sign;
my $response = LWP::UserAgent->new->post(
    $endpoint,
    Content_Type => 'application/x-www-form-urlencoded',
    Content => $request->to_post_body,
);

is($response->content, 'oauth_token=requestkey&oauth_token_secret=requestsecret');
