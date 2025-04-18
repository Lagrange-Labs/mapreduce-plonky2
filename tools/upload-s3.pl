#!/usr/bin/env perl
use v5.20;
use utf8;
use strict;
use warnings;
use autodie;
use File::Find;
use File::Basename;
use Cwd;

# Fetch the PPs directory from $ARGV[1]
my $pps_directory = shift;
say "Processing PPs from $pps_directory";

# Save the current dir
my $current_dir = getcwd;
# Go to the PPs directory
chdir $pps_directory;

# This will exit the script if any of the PPs are already present on S3
find({ wanted => \&check_not_on_s3, no_chdir => 1 }, '.');

# Go back to the saved invokation directory
chdir $current_dir;

# Recursively upload the PPs to S3
say "Uploading the PPs from $current_dir/$pps_directory to S3...";
system("aws s3 cp --no-progress --recursive $pps_directory s3://lagrange-public-parameters --endpoint-url=https://428e47101872e479a0c311b576430fac.r2.cloudflarestorage.com");
say "Done.";


#
# This subroutine exits with exit code 1 if the provided file already exists on S3
#
sub check_not_on_s3 {
  if (-f) {
    # Strip the ./ prefix
    my $filename = $_;
    $filename =~ s/^\.\///;
    print "Checking if `$filename` is present on S3... ";

    # Check if the file already exists on S3
    `aws s3 ls s3://lagrange-public-parameters/$filename --endpoint-url=https://428e47101872e479a0c311b576430fac.r2.cloudflarestorage.com`;

    # aws s3 ls returns 0 if the file has been found, 1 otherwise.
    if ($?) {
      say "no";
    } else {
      say "yes, exiting";
      exit 1;
    }
  }
}
