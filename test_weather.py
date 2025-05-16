import requests
key = '132a84233e6088a664b73e0ed8e91b7c'
r = requests.get(f'https://api.openweathermap.org/data/2.5/weather?q=Mumbai,IN&appid={key}&units=metric').json()
print(f"""Weather: {r['weather'][0]['description']}
Temperature: {r['main']['temp']}°C
Humidity: {r['main']['humidity']}%""") 