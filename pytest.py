from whois import whois

try:
    domain_info = whois("GOGGGGGLE.COM")
    
    # Check if the domain information is empty or not found
    if not domain_info or not domain_info.get("domain_name"):
        print("Not safe")
    else:
        print("Domain found and verified!")
        print(domain_info)
except Exception as e:
    # Gracefully handle the error and display the desired message
    print("Not safe")
