# Analyzing Suspicious Files and URLs-Using VirusTotal


![image](https://github.com/user-attachments/assets/d030b99a-9f49-4dc0-a640-2d79aef14b6e)

## Introduction

As part of my ongoing efforts to deepen my understanding of cybersecurity and enhance my skills in investigating and mitigating threats, I focused on leveraging VirusTotal for file and URL analysis. My goal was to gain hands-on experience in analyzing potentially malicious files and websites, identifying Indicators of Compromise (IOCs), and using VirusTotal's various features for comprehensive threat intelligence.

## Project Overview

The primary objective of this project was to examine suspicious files and URLs to determine their maliciousness. VirusTotal, a widely used tool in the cybersecurity community, aggregates results from multiple antivirus engines and security vendors to provide detailed insights into files and URLs. Through this project, I aimed to:

## Understand how to interpret the VirusTotal output.

Examine the "Detection," "Behavior," and "Relations" sections of a suspicious file's analysis.
Perform a URL scan to identify harmful links and their associated connections.
Search for IOCs like file hashes and IP addresses to detect malicious activities and correlations.
Methodology

### File Analysis with VirusTotal
I uploaded a suspicious file with the SHA256 hash “415ba65e21e8de9196462b10dd17ab81d75b3e315759ecced5ea8f5812000c1b” to VirusTotal. The analysis revealed that 42 out of 58 security vendors flagged this file as malicious, indicating that it was indeed harmful. By examining the tags, I learned that the file contained macros and was obfuscated, which are common traits of malware.

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image.png)

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-1-1024x539.png)

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-4-1024x378.png)
![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-5-1024x273.png)

### URL Scanning with VirusTotal

I proceeded to analyze a suspicious URL, “thuening[.]de[/]cgi-bin/uo9wm/,” using VirusTotal. The URL scan returned links to other potentially harmful sites, and I examined the “Links” section to understand how malicious URLs might redirect users to dangerous destinations. I also noted that URLs, even if they didn’t contain harmful content directly, could lead to malicious websites, emphasizing the importance of continuing investigations when any suspicious link is identified.

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-10.png)

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-11-1024x594.png)
![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-12.png)

### Searching for Indicators of Compromise (IOCs)

Throughout my investigation, I made use of VirusTotal's "Search" feature to look up IOCs, such as file hashes, IP addresses, and URLs. For instance, I searched the hash value of the suspicious file mentioned earlier and found past analysis results. Additionally, I examined IP addresses connected to the file and found multiple associated files, including “SplitPath” and “TestMfc,” which helped me understand the broader context of the attack.

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-14.png)

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-15-1024x406.png)

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-16-1024x531.png)

![image](https://github.com/user-attachments/assets/bb54b644-9aae-4db1-bcd0-8f707023c56a)

### Findings and Observations

Detection

The "Detection" section of VirusTotal provided valuable insight into how different security vendors classify the file. It highlighted the importance of reviewing different AV vendors' perspectives on the file to get a holistic view of its behavior.

Behavior

The "Behavior" section showed various activities performed by the file, including network connections and DNS queries. This section provided me with a detailed breakdown of the file’s actions, which are crucial for understanding how malware operates once it infects a system.

![image](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-20-1024x334.png)

Relations

By analyzing the “Relations” tab, I could trace the connections between the file and external domains or IP addresses, identifying potential command-and-control centers and other compromised assets. This helped me build a clearer picture of the malicious infrastructure tied to the attack.

### Challenges and Lessons Learned

While using VirusTotal, I encountered challenges, especially when dealing with newer types of malware that exhibited non-static behaviors. In such cases, static and dynamic analysis alone might not be enough. I learned that ongoing monitoring of threats, including reviewing historical VirusTotal reports, can help paint a more complete picture of the threat landscape.

Additionally, I realized the importance of considering the context of the attack. If a file or URL has been analyzed in the past, it’s likely part of a larger campaign affecting multiple organizations. This knowledge can guide incident response efforts and help organizations better prepare for similar attacks in the future.

### Conclusion

This project was an eye-opener into the real-world process of investigating suspicious files and URLs. By utilizing VirusTotal’s extensive tools, I gained deeper insight into how malware behaves, how threats are detected, and how IOCs can be correlated to identify ongoing attacks. Moving forward, I plan to continue exploring these tools, applying them to my Blue Team projects, and enhancing my skills in threat hunting and incident response.

### Personal Reflection

Through this project, I’ve reinforced my understanding of the importance of proactive threat intelligence in cybersecurity. By combining knowledge from file analysis, URL scanning, and IOC searching, I’ve developed a more comprehensive approach to investigating potential threats. This experience will undoubtedly benefit my ongoing work as a SOC Analyst and Cybersecurity Specialist, and I look forward to applying these insights to future security challenges.

