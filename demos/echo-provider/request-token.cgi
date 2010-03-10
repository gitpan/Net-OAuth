#!/opt/local/bin/perl

use strict;
use warnings;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use lib qw(../../lib);
use Net::OAuth;
use URI;

my $q = new CGI;

use Data::Dumper;
$Data::Dumper::Terse=1;
$Data::Dumper::Useqq=1;

my $request = eval {Net::OAuth->request("request token")->from_hash({$q->Vars},
    request_url => $q->url,
    request_method => $q->request_method,
    consumer_secret => 'secret',
)};

if ($@) {
    print $q->header(-status => '400 Invalid Request', -type => 'text/plain');
    print "Invalid request: $@\n";
    print "Vars", Dumper({$q->Vars});
    print "Query", Dumper({URI->new($q->url(-query=>1))->query_form});
    print "Env: ", Dumper(\%ENV), "\n";
    exit;
}

print STDERR $request->signature_base_string;

if (!$request->verify) {
    print $q->header(-status => '400 Signature verification failed', -type => 'text/plain');
    print "Signature verification failed.\n";
    print "Base string: ", $request->signature_base_string, "\n";
    print "Vars", Dumper({$q->Vars});
    print "Env: ", Dumper(\%ENV), "\n";
    exit;
}
else {
    # Service Provider sends Request Token Response

    my $response = Net::OAuth->response("request token")->new( 
        token => 'request-token',
        token_secret => 'request-secret',
    );
    
    print $q->header('text/plain');
    print $response->to_post_body;
}    
