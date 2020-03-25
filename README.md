# About

Lite version of [ShodanHat](https://github.com/HatBashBR/ShodanHat) with Python3 supporting.

# Dependencies

```
pip install -r requirements.txt
```

# Options

```
-h, --help                 show this help message and exit
-i IP, --ip=IP             info about one host
-l LIST, --list=LIST       info about a list of hosts
-r RANGE, --range=RANGE    scan a range of ips. ex: 192.168.1.1-192.168.1.255
-o OUTPUT, --output=OUTPUT specify a output file
--setkey=SETKEY            set your api key automatically
```

# Usage

```
python shodan-search.py -i <ip-address> --setkey <shodan-api-key>
```

# Credits

All credit goes to [HatBashBR](https://github.com/HatBashBR).