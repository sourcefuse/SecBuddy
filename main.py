# import the package
from PyBurprestapi import burpscanner
import time
import os
import sys
import tempfile
import requests
import argparse



def active_scan(api_port, target_url, proxy_url):
    """Send a URL to Burp to perform active scan"""
    try:
        r = requests.post(
            "{}:{}/burp/scanner/scans/active?baseUrl={}".format(
                proxy_url,
                api_port,
                target_url
            )
        )
        r.raise_for_status()
        print("[-] {} Added to the scan queue".format(target_url))
    except requests.exceptions.RequestException as e:
        print("Error adding {} to the scan queue: {}".format(target_url, e))
        sys.exit(1)

def parse_cmd_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'proxy_url',
        type=str,
        help="Burp Proxy URL"
    )
    parser.add_argument(
        '-pP', '--proxy-port',
        type=str,
        default=8080,
        # metavar='',
        # help="Burp Proxy Port (default: 8080)"
    )
    parser.add_argument(
        '-aP', '--api-port',
        type=str,
        default=8090,
        # metavar='',
        # help="Burp REST API Port (default: 8090)"
    )
    parser.add_argument(
        '-t', '--target',
        type=str,
        default="in-scope",
        # metavar='',
        # help="Reports: all, in-scope (default: in-scope)"
    )
    return parser.parse_args()

def main():
    args = parse_cmd_line_args()
    # setup burp connection
    host = '{}:{}'.format(args.proxy_url,args.api_port)
    api_port = args.api_port
    proxy_url = args.proxy_url
    target_url = []
    target_url = args.target
    url_prefix = "ALL"
    rtype = "HTML"
    bi = burpscanner.BurpApi(host)

    ## Report 
    def scan_report(api_port, proxy_url, rtype, url_prefix):
        """
        Downloads the scan report with current Scanner issues for
        URLs matching the specified urlPrefix (HTML/XML)
        """
        try:
            if url_prefix == "ALL":
                r = requests.get(
                    "{}:{}/burp/report?reportType={}".format(
                        proxy_url,
                        api_port,
                        rtype
                    )
                )
            else:
                r = requests.get(
                    "{}:{}/burp/report?urlPrefix={}&reportType={}".format(
                        proxy_url,
                        api_port,
                        url_prefix,
                        rtype
                    )
                )
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("Error downloading the scan report: {}".format(e))
        else:
            print("[+] Downloading HTML/XML report for {}".format(url_prefix))
            # Write the response body (byte array) to file
            file_name = "burp-report_{}_{}.{}".format(
                time.strftime("%Y%m%d-%H%M%S", time.localtime()),
                url_prefix.replace("://", "-"),
                rtype.lower()
            )
            file = os.path.join(tempfile.gettempdir(), file_name)
            with open(file, 'wb') as f:
                f.write(r.text)
            print("[-] Scan report saved to {}".format(file))
            return file_name

    # Scan issues
    def scan_issues(api_port, proxy_url, url_prefix):
        """
        Returns all of the current scan issues for URLs
        matching the specified urlPrefix
        """
        try:
            if url_prefix == "ALL":
                r = requests.get(
                    "{}:{}/burp/scanner/issues".format(
                        proxy_url,
                        api_port,
                    )
                )
            else:
                r = requests.get(
                    "{}:{}/burp/scanner/issues?urlPrefix={}".format(
                        proxy_url,
                        api_port,
                        url_prefix
                    )
                )
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("Error getting the scan issues: {}".format(e))
        else:
            resp = r.json()
            if resp['issues']:
                print("[+] Scan issues for {}:".format(url_prefix))
                uniques_issues = {
                    "Issue: {issueName}, Severity: {severity}".format(**issue)
                    for issue in resp['issues']
                }
                for issue in uniques_issues:
                    print("  - {}".format(issue))
                return True
            else:
                return False


    #### get scan status
    def scan_status(api_port, proxy_url):
        """Get the percentage completed for the scan queue items"""
        try:
            r = requests.get(
                "{}:{}/burp/scanner/status".format(proxy_url, api_port)
            )
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("Error getting the scan status: {}".format(e))
        else:
            resp = r.json()
            sys.stdout.write("\r[-] Scan in progress: %{}".format(
                resp['scanPercentage'])
            )
            sys.stdout.flush()
            return resp['scanPercentage']


    # Add target in burp scope
    burp_scope = bi.burp_scope(target_url)

    # Add target to scope 
    burp_scope_add = bi.burp_scope_add(target_url)

    # Add to spider
    burp_spider = bi.burp_spider(target_url)

    # Start active scan
    active_scan(api_port, target_url, proxy_url)

    # Get the scan status
    # while scan_status(api_port=args.api_port,
    #                           proxy_url=args.proxy_url) != 1:
    #             time.sleep(20)
    #             print("\n[+] Scan completed")
    # resp = scan_status(api_port=args.api_port,
    #                            proxy_url=args.proxy_url)
    resp =0

    while (int(resp)!=10):
        resp = scan_status(api_port=args.api_port,
                               proxy_url=args.proxy_url)
        time.sleep(20)
    print("\n[+] Scan completed")

    # Get issue list
    scan_issues(api_port,proxy_url,url_prefix)
    rfile = scan_report(
                api_port,
                proxy_url,
                rtype,
                url_prefix)
if __name__ == '__main__':
    #print(ASCII)
    main()





