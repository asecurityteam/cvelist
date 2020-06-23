# Internal cvelist.

**Shortlink: [http://go/internal-cvelist](http://go.atlassian.com/internal-cvelist)**

This is the internal cvelist repository for managing [CVE](https://cve.mitre.org) ids allocated to the [Atlassian](http://go.atlassian.com/cna) [CNA](https://cve.mitre.org/cve/request_id.html#cna_participants).


### Setup

Create a python 3 virtualenv.

For example,

    # using virtualenv via virtualenvwrapper:
    mkvirtualenv -p /usr/bin/python3 cvelist

    # or by using Pipenv
    pipenv shell --three

Install the requirements:

    pip install -r requirements.txt


### Adding new CVE ranges

1. create a new git branch, e.g. `git checkout -b <adding-cve-id-range-2018-01-31>`
2. modify [`cve_id_ranges.json`](cve_id_ranges.json) to specify the new range(s).
3. run `python validator.py`
4. raise a pull request to get the changes merged.

### Reserving a CVE id

1. run `git remote update`
2. run `python -m scripts.reserve_a_cve_id <year that the issue was discovered in>`
3. modify the cve id file that the script has allocated by:
    1. providing the name of the product as the value for `product_name`, for example `Bamboo`.
    2. providing affected version information in `version_data` `version_value`(s).
    3. providing at least one url in `reference_data` section containing the issue(s) you want to detail.
    4. provide information on the problem type under `problemtype`, for example `Cross Site Scripting (XSS)`.
    5. provide a description under `description_data` that conforms with the [CNA rules](https://cve.mitre.org/cve/cna/CNA_Rules_v2.0.pdf) (see appendix B).
4. run `python validator.py`
5. raise a pull request to get the changes merged.

### What if there are no CVE ids left?

If you are not a part of Product Security team, then ask the `!engdisturbed` in the Slack \#help-security room to ask Mitre for more CVE ids.

However, if you are part of Product Security then:

1. go to [https://cveform.mitre.org/](https://cveform.mitre.org/)
2. Select "Request a block of IDs (For CNAs Only)"
3. enter security@atlassian.com for the email address.
4. request 10 more CVE ids.
5. wait for Mitre to respond via email to provide the CVE ids, you will need to monitor incoming issues on the [securitysd.atlassian.net instance](https://securitysd.atlassian.net/issues/?jql=text%20~%20"mitre"%20and%20resolution%20is%20empty).
6. follow the instructions above on how to add new CVE ids to this repository.

### Syncing with the public cvelist

**First** you need to clone the [public cvelist repository](https://github.com/CVEProject/cvelist) onto your machine.

Then you can use the `scripts/sync_with_public_cvelist.py` script to synchronise between the internal cvelist and the public one.
Information on using the sync script can be obtained by running

    python -m scripts.sync_with_public_cvelist -h

