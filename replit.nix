{pkgs}: {
  deps = [
    pkgs.file
    pkgs.metasploit
    pkgs.python312Packages.gvm-tools
    pkgs.tshark
    pkgs.nmap
    pkgs.inetutils
  ];
}
