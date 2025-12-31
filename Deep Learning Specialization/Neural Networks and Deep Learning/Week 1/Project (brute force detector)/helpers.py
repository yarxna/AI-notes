import ipaddress, random

def generate_public_ip():
    while True:
        oc = [random.randint(0, 255) for _ in range(4)]
        ip_str = ".".join(map(str, oc))

        try:
            ip = ipaddress.IPv4Address(ip_str)

            if (
                not ip.is_private and
                not ip.is_loopback and
                not ip.is_multicast and
                not ip.is_link_local and
                not ip.is_reserved and
                ip_str != "0.0.0.0" and
                not 224 <= oc[0] <= 239
            ):
                return str(ip)
        except:
            continue

def generate_user_agent():
    os_devices = [
        ("Windows NT 10.0; Win64; x64", "desktop", "windows"),
        ("Windows NT 6.1; Win64; x64", "desktop", "windows"),
        
        ("Macintosh; Intel Mac OS X 10_15_7", "desktop", "macos"),
        ("Macintosh; Intel Mac OS X 11_2_3", "desktop", "macos"),
        ("Macintosh; Intel Mac OS X 12_6", "desktop", "macos"),
        
        ("X11; Linux x86_64", "desktop", "linux"),
        ("X11; Ubuntu; Linux x86_64", "desktop", "linux"),
        
        ("Linux; Android 13; SM-S901B", "mobile", "android"),
        ("Linux; Android 12; Pixel 6", "mobile", "android"),
        ("Linux; Android 11; SM-G998B", "mobile", "android"),
        ("Linux; Android 13; SM-X710", "tablet", "android"),
        
        ("iPhone; CPU iPhone OS 17_2 like Mac OS X", "mobile", "ios"),
        ("iPhone; CPU iPhone OS 16_6 like Mac OS X", "mobile", "ios"),
        ("iPad; CPU OS 17_2 like Mac OS X", "tablet", "ios"),
        ("iPad; CPU OS 16_6 like Mac OS X", "tablet", "ios"),
    ]

    os_string, device_type, os_type = random.choice(os_devices)

    if os_type == "android":
        if random.random() < 0.15: 
            samsung_versions = ["21.0", "20.0", "19.0"]
            chrome_version = random.choice(["120.0.0.0", "119.0.6045.163", "118.0.5993.111"])
            samsung_version = random.choice(samsung_versions)
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/{samsung_version} Chrome/{chrome_version} Mobile Safari/537.36"
        else: 
            chrome_versions = ["120.0.0.0", "119.0.6045.163", "118.0.5993.111", "117.0.5938.153"]
            chrome_version = random.choice(chrome_versions)
            suffix = "Mobile" if device_type == "mobile" else ""
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} {suffix}Safari/537.36".strip()
    
    elif os_type == "ios":
        ios_versions = ["17.2", "17.1", "16.6", "16.5"]
        ios_version = random.choice(ios_versions)
        
        if device_type == "mobile":
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ios_version} Mobile/15E148 Safari/604.1"
        else:  
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ios_version} Safari/604.1"
    
    elif os_type == "windows":
        browser_choice = random.random()
        
        if browser_choice < 0.65: 
            chrome_versions = ["120.0.0.0", "119.0.6045.159", "118.0.5993.89", "117.0.5938.149"]
            chrome_version = random.choice(chrome_versions)
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
        
        elif browser_choice < 0.85:  
            firefox_versions = ["121.0", "120.0", "119.0", "118.0"]
            firefox_version = random.choice(firefox_versions)
            return f"Mozilla/5.0 ({os_string}; rv:{firefox_version}) Gecko/20100101 Firefox/{firefox_version}"
        
        else: 
            edge_versions = ["120.0.0.0", "119.0.2151.97", "118.0.2088.76", "117.0.2045.47"]
            edge_version = random.choice(edge_versions)
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{edge_version} Safari/537.36 Edg/{edge_version}"
    
    elif os_type == "macos":
        browser_choice = random.random()
        
        if browser_choice < 0.4: 
            safari_versions = ["17.2", "17.1", "16.6", "16.5"]
            safari_version = random.choice(safari_versions)
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_version} Safari/605.1.15"
        
        elif browser_choice < 0.8: 
            chrome_versions = ["120.0.0.0", "119.0.6045.159", "118.0.5993.89", "117.0.5938.149"]
            chrome_version = random.choice(chrome_versions)
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
        
        else: 
            firefox_versions = ["121.0", "120.0", "119.0", "118.0"]
            firefox_version = random.choice(firefox_versions)
            return f"Mozilla/5.0 ({os_string}; rv:{firefox_version}) Gecko/20100101 Firefox/{firefox_version}"
    
    else:  
        browser_choice = random.random()
        
        if browser_choice < 0.7: 
            chrome_versions = ["120.0.0.0", "119.0.6045.159", "118.0.5993.89"]
            chrome_version = random.choice(chrome_versions)
            return f"Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
        
        else: 
            firefox_versions = ["121.0", "120.0", "119.0"]
            firefox_version = random.choice(firefox_versions)
            return f"Mozilla/5.0 ({os_string}; rv:{firefox_version}) Gecko/20100101 Firefox/{firefox_version}"

