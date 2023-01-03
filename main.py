import requests

def check_website_status(url):
  try:
    # Forcefully add "https://" to the beginning of the URL if it is not present
    if not url.startswith("https://"):
      url = "https://" + url

    r = requests.get(url)
    if r.status_code == 200:
      return "Operational"
  except:
    return "Service status is DOWN"

# Prompt the user to enter a website URL
url = input("Enter a website URL: ")

# Remove the prefix leading up to the "//" symbol
url = url.split("//")[-1]

# Check the status of the website
status = check_website_status(url)

# Print the status next to the website URL
print(f"{url}: {status}")