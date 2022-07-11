#! /usr/bin/perl 
use LWP::Simple;
use LWP::UserAgent; # These two used to get HTTP content, status codes.
use JSON;
use Data::Dumper; # These two used to translate the JSON users list to an array.
print "wordpress-detect 1.0 - Quickly scan a website to see if it is a Wordpress site, enumerate users, and detect a web application firewall (WAF).\nAuthor: Christopher Pace\n\n";
my $target = $ARGV[0];
if ($target eq ""){
print "ERROR: No domain to scan.\nUse: wordpress-detect.pl \{domain\}\n";
exit;
}
my $wordpress_prob = 0;
my $waf = 0;
my $xmlrpc = getprint ("http://${target}/xmlrpc.php"); # xmlrpc.php - external interface for WordPress, 405 is the normal response, 403 is a WAF blocking it.
my $feed = getprint ("http://${target}/feed/"); # WordPress feed - can be blocked by a WAF, or maybe not even WordPress at all.
my $users = getprint ("http://${target}/wp-json/wp/v2/users"); # Username enumeration, specific to WordPress and blocked by a WAF.
my $license = getprint ("http://${target}/license.txt"); # Presence of a license file, 403 is a WAF, 200 can be WordPress or not, which we'll examine.
my $wp_content = getprint ("http://${target}/wp-content/"); # Default directory of WordPress content, 403 with a generic user agent is a huge sign a WAF is present.  We'll test it with a modified user agent string later.
if ($xmlrpc =~ /405/){ 
print "Hit for XML-RPC page.  prob add 2\n";
$wordpress_prob = $wordpress_prob + 2;
print "Probabability: $wordpress_prob\n";
}
if ($xmlrpc =~ /403/){
print "Forbidden for XML-RPC page.  prob add 1\n";
$wordpress_prob = $wordpress_prob + 1;
$waf = $waf + 2;
print "Probabability: $wordpress_prob\n";
}
if ($feed =~ /403/){
print "Forbidden on feed, prob is 1\n";
$waf = $waf + 1;
$wordpress_prob = $wordpress_prob + 1;
print "Probability: $wordpress_prob\n";
}
if ($feed =~ /200/) { # If we got a 200 status on the feed, let's switch to get instead of getprint to look at the content as well.
    $feed = get ("http://${target}/feed/");
if ($feed =~ /wordpress/){
print "WordPress in feed, prob is 3 for WordPress itself.\n";
$wordpress_prob = $wordpress_prob + 3;
print "Probability: $wordpress_prob\n";
}
}
if ($users =~ /403/){
print "Forbidden on users, prob is 1 for both WAF and WordPress.\n";
$waf = $waf + 1;
$wordpress_prob = $wordpress_prob + 1;
print "Probability: $wordpress_prob\n";
my $ua = LWP::UserAgent->new(); #Switching user agent on the users list
$ua->agent('Mozilla/5.0 (Windows NT 10.0) like Gecko');
$response = $ua->get ("http://${target}/wp-json/wp/v2/users");    
if ($response->decoded_content =~ /"slug":/){
print "slug in users list, had to change user agent.  prob is 3, waf is 2.\n";
$wordpress_prob = $wordpress_prob + 3;
$waf = $waf +2;
print "Probability: $wordpress_prob\n";
my $json_users = from_json($response->decoded_content);
for (my $i=0;$i<@$json_users;$i++){
push (@usernames , $json_users->[$i]->{'slug'}); #Storing the usernames into an array we will call later in the results.
}
} else {
if ($response->status_line =~ /401/){
print "Forbidden even after changing user agent on users list.  prob is 1, WAF is 2.\n";
$waf = $waf + 2;
$wordpress_prob = $wordpress_prob + 1;
print "Probability: $wordpress_prob\n";
}
}
}
if ($users =~ /401/){
print "REST error on users, prob is 1, waf is 2\n";
$wordpress_prob = $wordpress_prob + 1;
$waf = $waf + 2;
print "Probability: $wordpress_prob\n";
}
if ($users =~ /200/) { # If we got a 200 status on the users, let's switch to get instead of getprint to look at the content as well.
my $ua = LWP::UserAgent->new();
$ua->agent('Mozilla/5.0 (Windows NT 10.0) like Gecko');
$response = $ua->get ("http://${target}/wp-json/wp/v2/users"); # Changing the user agent again, too many sites block this.
if ($response->decoded_content =~ /"slug":/){
print "slug in users list, prob is 3\n";
$wordpress_prob = $wordpress_prob + 3;
print "Probability: $wordpress_prob\n";
my $json_users = from_json($response->decoded_content);
for (my $i=0;$i<@$json_users;$i++){
push (@usernames , $json_users->[$i]->{'slug'}); #Storing the usernames into an array we will call later in the results.
}
} 
}
if ($license =~ /403/){
print "Forbidden on license, prob is 0, but WAF add 1\n";
$waf = $waf + 1;
print "Probability: $wordpress_prob\n";
}
if ($license =~ /200/) { # If we got a 200 status on the license.txt, let's switch to get instead of getprint to look at the content as well.
    $license = get ("http://${target}/license.txt");
if ($license =~ /WordPress/){
print "WordPress in license, prob is 4\n";
$wordpress_prob = $wordpress_prob + 4;
print "Probability: $wordpress_prob\n";
} 
} # wp-content start
if ($wp_content =~ /403/){
print "Forbidden on wp-content, prob is 1, WAF add 1\n";
$waf = $waf + 1;
$wordpress_prob = $wordpress_prob + 1;
print "Probability: $wordpress_prob\n";
}
if ($wp_content =~ /404/){
print "404 on wp-content, prob is -1, WAF add 0\n";
$wordpress_prob = $wordpress_prob - 1;
print "Probability: $wordpress_prob\n";
}
if ($wp_content =~ /200/) { # If we got a 200 status on the wp-content, let's switch to get instead of getprint to look at the content as well.
    $wp_content = get ("http://${target}/wp-content/");
if ($wp_content eq ""){ #Wp-content is empty, means WordPress
print "Wp-content is empty, prob is 3\n";
$wordpress_prob = $wordpress_prob + 3;
print "Probability: $wordpress_prob\n";
} 
} 
if ($wp_content == "403"){ # Ok, we got a 403.  That's fine, but what happens if we change the user agent string?
print "Forbidden on wp-content, changing user agent and trying again.\n";
my $ua = LWP::UserAgent->new();
$ua->agent('Mozilla/5.0 (Windows NT 10.0) like Gecko');
$response = $ua->get ("http://${target}/wp-content/");
if ($response->decoded_content eq ""){ #Wp-content is empty, means WordPress
print "Wp-content is empty, had to use custom user agent.  prob is 3, waf is 2.\n"; # Gotya, WAF.
$wordpress_prob = $wordpress_prob + 3;
$waf = $waf + 2;
print "Probability: $wordpress_prob\n";
} else{
print "wp-content not blank, not WordPress.  Probability goes -1, WAF +1\n";
$wordpress_prob = $wordpress_prob - 1;
$waf = $waf + 1;
}
}
print "\n\n\n\n\n\n-----Results:----\n" , "Probability site is a WordPress site: " , int($wordpress_prob/11*100) , "\%\nProbability of a Web Application Firewall or WordPress security plugin present: " , int($waf/8*100) , "\%\nUsernames Enumerated:\n";
if (@usernames){
for (my $i=0;$i<@usernames;$i++){
print @usernames[$i] , "\n";
}
}
else{
print "No usernames enumerated.  Womp-womp.\n";
}
