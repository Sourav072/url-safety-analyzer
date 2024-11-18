URL Safety Analyzer: Setup Instructions
This project analyzes the safety of URLs by performing the following:

Domain age and SSL validity checks
VirusTotal API scan results
Overall safety score with a visual representation (pie chart)
Requirements
Python 3.x: Ensure Python is installed on your system.
Dependencies: Install the required Python libraries.

Step-by-Step Setup
1. Clone the Repository
Clone the repository to your local machine:

bash
Copy code
git clone https://github.com/Sourav072/url-safety-analyzer.git
cd url-safety-analyzer

2. Set Up a vt.env File
Create a .env file named vt.env in the project directory to store your VirusTotal API key:

Open a terminal and create the file:

bash
Copy code
nano vt.env
Add the following line to the file:

makefile
Copy code
VIRUSTOTAL_API_KEY=your_api_key_here
Replace your_api_key_here with your VirusTotal API key.

Save and exit the file (in nano, press Ctrl+O to save and Ctrl+X to exit).

3. Install Dependencies
Install the required Python libraries by running:

bash
Copy code
pip install -r requirements.txt
If no requirements.txt is available, manually install the dependencies:

bash
Copy code
pip install requests beautifulsoup4 whois matplotlib cryptography python-dotenv

4. Run the Script
Run the script to analyze a URL:

bash
Copy code
python url_safety_analyzer.py
5. Analyze URLs
Enter a URL (e.g., https://example.com) when prompted.
The script will:
Fetch the URL content
Check the domain's age and SSL certificate
Scan the URL using VirusTotal
Display the results as a total safety score and a pie chart visualization.
Example Output
Prompt:

mathematica
Copy code
=== Welcome to the URL Safety Analyzer ===
Enter the URL to analyze:
Input a URL like https://example.com.

Output:

vbnet
Copy code
Analyzing: https://example.com
Total Security Score: 85/100
Recommendation: The link appears relatively safe to use.
Pie Chart: A pie chart visualization of the analysis results will be displayed.

Notes for Users
Ensure your VirusTotal API key is valid. You can obtain a free API key by signing up on VirusTotal.
If you encounter issues with dependencies, ensure you are using Python 3.x and pip is installed correctly.
