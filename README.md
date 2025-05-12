# A Technical Exploration of AWS Security Hub Data Enrichment

This repository contains example data and proof of concept code for our Bachelor's thesis in Digital Infrastructure and Cyber Security:  
"A Technical Exploration of AWS Security Hub Data Enrichment".  

The `example_data/` directory contains files that correlate to the same finding, but follow the format of the different AWS services such as GuardDuty, Security Hub and Detective. There is also an additional file that highlights the enrichment of the previously mentioned finding.

The `proofs_of_concept/` directory contains three different directories&mdash;all of which represent their respective proof of concept.  

`busy_waiting/`, `exponential_backoff/` and `scheduled/` house the files that run on their respective Lambda functions in AWS.

```
.
└── A-Technical-Exploration-of-AWS-Security-Hub-Data-Enrichment/
    ├── example_data/
    │   ├── detective_data.json
    │   ├── finding_enrichment.json
    │   ├── guardduty_finding.json
    │   └── security_hub_finding.json
    └── proofs_of_concept/
        ├── busy_waiting/
        │   └── lambda.py
        ├── exponential_backoff/
        │   ├── 01_InitiateInvestigation.py
        │   ├── 02_StatusCheck&Combine.py
        │   ├── 03_IncreaseWaitTime.py
        │   └── s1_MainStepFunction.json
        └── scheduled/
            ├── start_investigation.py
            ├── poll_investigations.py
            └── process_investigation.py
```
