# wordpress-detect
wordpress-detect - Quickly scan a website to see if it is a Wordpress site, enumerate users, and detect a web application firewall (WAF).


Requirements: 

Perl 

LWP::Simple

JSON

This Perl script attempts to determine if a website is running WordPress, whether or not a web application firewall (WAF) is in use, and also attempts to enumerate WordPress users. You might wonder why you wouldn't just use WPScan, which enumerates users and vulnerable versions (this script does not enumerate vulnerabilities).  The answer is that with a web application firewall or security plugin in use, WPScan typically fails to recognize whether or not a site is running WordPress.  Also, this script takes 5-10 seconds to run on average, which is incredibly fast compared to WPScan.  If you have a lot of sites to scan, WPScan starts to become less effective.  Instead, this script will quickly decide the probability that the site is indeed a WordPress site, where you can then push it off to WPScan if you would like.

This script uses a scoring system to determine if Wordpress is present, as opposed to relying on a single artifact.  While it only tests 5-8 pages on the site, real-world testing gives an average of 90% reliability of detecting a WordPress site when the reported probability is 40% or higher.  The WAF detection is purely based off these 5-8 pages, so it is less reliable to tell if a WAF in general is configured, and insteads concentrates on the detection of WordPress security plugins that block or control access to key resources.  You can see the logic behind the probability calculations in the output of the script, as well as tweak those values to your liking if necessary.

Use: wordpress-detect.pl domain

To install Perl dependencies:

cpan install LWP::Simple JSON
