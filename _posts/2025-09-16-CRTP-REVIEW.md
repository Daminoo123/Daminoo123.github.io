---
layout: post
title: "My CRTP Journey – Insights & Experience 🚀"
date: 2025-06-16 14:45:00 -0500
categories: Certifications
permalink: /certifications/2025/06/16/CRTP-REVIEW/
---

Hi, I’m **Mohamed Amine Ben Aoun** a Network infrastructure and data security engineering student at ESPRIT.  
Recently, I had the incredible opportunity to take the **Certified Red Team Professional (CRTP)** exam, which I earned through a giveaway. In this post, I’ll share my experience with the course, lab environment, exam, and a few tips for anyone planning to pursue this certification.
## What is CRTP?

The **CRTP** is a hands-on certification designed for those looking to deepen their skills in Active Directory security and red teaming. Unlike theory-heavy exams, CRTP requires you to work in a realistic Windows lab setup with multiple domains and Server 2022+ machines. Your goal is to navigate, exploit, and analyze the network — all within a limited timeframe — and submit a full report documenting your steps.

For a long time, I had considered pursuing the CRTP certification. I'd been building my practical skills on HackTheBox but lacked a formal credential to validate them. I was thrilled, therefore, to get the chance to participate after unexpectedly winning access through a giveaway—a huge thanks to Altered Security for the opportunity.  

![CRTP Certificate]({{ '/imgs/CRTP/Win.png' | relative_url }})

## Topics Covered

The course dives into many practical aspects of Active Directory and offensive security, including:

- Fundamentals of Active Directory and its core features  
- Enumerating users, computers, and groups  
- Offensive PowerShell and .NET techniques  
- Escalating privileges locally and across domains  
- Lateral movement strategies and network pivoting  
- Maintaining access and persistence in AD environments  
- Exploiting trust relationships between domains  
- Bypassing security tools like AV, Microsoft Defender for Endpoint (MDE), and Microsoft Defender for Identity (MDI)

The material is clearly structured, and I found that it helped me solidify concepts that had been tricky when learning independently.

## Lab Experience

The included lab environment is reliable and well-maintained. I didn’t run into connection issues, and in the exam, it’s recommended to connect to the server closest to your location for the smoothest experience.

## Exam Format

The CRTP exam is a 24-hour hands-on challenge. You get a total of 25 hours for the lab, which includes an extra hour for setup. Unlike the lab machines, you won't find ready-to-use tools on the exam machines; you'll need to import your own. The platform provides access to a downloadable `tools.zip` folder, which contains all the tools used in the course. The exam consists of five target machines, each with different configurations and applications. The goal is to achieve **command execution on all targets**, but administrative privileges are not required.

A full report must be submitted within 48 hours after finishing the lab. This report should contain:

- Step-by-step walkthroughs of compromises  
- Screenshots and outputs from tools used  
- Detailed explanations of techniques and strategies  
- Optional mitigations or references to external resources for bonus points  

## Difficulties Encountered

During the exam, I encountered a few challenges:

- I managed to **escalate privileges on the local machine** and **compromise the first three machines** in about 2.5 hours.  
- Pivoting from the third machine to the fourth initially slowed me down. I had assumed that the **only tools I need to use were from the `tools.zip` folder**, even though the attack path was clearly visible with an other tool.  
- Some tools from the zip folder, like **Rubeus**, were behaving unexpectedly. To resolve this, I **downloaded the latest versions from GitHub**, which allowed me to successfully continue the attack chain.

These difficulties were a good reminder to stay flexible and verify tool behavior during hands-on engagements.


## Practical Tips
Here are some tips that helped me throughout:

- Restart lab machines if necessary, as occasional misconfigurations may occur  
- Keep notes handy — they will save a lot of time during the exam 
- Capture evidence continuously for the report take as many screen shots as you can you wont regret it and they are free after all 

- Keep thorough notes from your preparation  
- Restart machines if something seems off  
- Take short breaks to maintain focus  
- Have your course and lab notes open for reference  
- Drink water and pace yourself during the marathon exam  
- Start the report as early as possible — don’t wait until the end  

## Final Thoughts

I found the CRTP to be an exceptional learning experience that perfectly balances practical challenges with comprehensive education. The course material is incredibly hands-on, the lab environment remains remarkably stable throughout the training period, and the support team responds with impressive speed and expertise. This certification serves as an outstanding gateway into Active Directory security and real-world red teaming operations. Having the opportunity to access this valuable training through their giveaway program added an extra layer of gratitude to the entire journey.

Next on my path is the **Certified Red Team Expert (CRTE)**, and I’m looking forward to sharing that journey as well.

Stay tuned for more posts on Active Directory security and red teaming! 🚀
![CRTP Certificate]({{ '/imgs/CRTP/Certificate.png' | relative_url }})