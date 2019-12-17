#!/usr/bin/python
import collections
import json
import os
import re
import subprocess
import sys

from . import utils


def get_used_cve_id_from_git_branches():
    """ yields cve ids from git branches of this repository. """
    cve_pattern = re.compile(r'(CVE-\d+-\d+)')
    git_command = [
        'git', 'branch', '-a', '--list', '*CVE*',
        '--format', '%(refname:short)']
    cve_branch_exe = subprocess.Popen(git_command, stdout=subprocess.PIPE)
    out, err = cve_branch_exe.communicate()

    for line in out.decode().split(os.linesep):
        line = line.strip()
        match = cve_pattern.search(line)
        if match is None:
            continue
        cve_id = match.group()
        yield cve_id


def get_free_cve_ids(used_cve_ids, files):
    """ yields free (reserved) cve ids and matching cve id file path. """
    for a_file in sorted(files):
        existing_json_data = utils.get_info_from_cve_json_file(a_file)
        state = utils.get_state_from_cve_json(existing_json_data)
        if state != 'RESERVED':
            continue
        cve_id = existing_json_data['CVE_data_meta']['ID']
        if cve_id not in used_cve_ids:
            yield (cve_id, a_file)


def load_template(name='base.json'):
    """ returns the loaded template file. """
    template_dir = os.path.join(
        utils.get_internal_cvelist_location(),
        'templates')
    with open(os.path.join(template_dir, name), 'r') as f:
        return json.load(f, object_pairs_hook=collections.OrderedDict)


def reserve_cve_id(cve_id, filepath):
    """ setups up the cve id for reservation. """
    output_json = load_template()
    output_json['CVE_data_meta']['ID'] = cve_id
    with open(filepath, 'w') as f:
        json.dump(output_json, f, indent=3)


def reserve_cve_id_in_git(cve_id):
    """ reserves the cve id in git by creating a branch for it. """
    subprocess.check_call(['git', 'checkout', '-q', '-b', cve_id])
    subprocess.check_call(['git', 'push', '-q', 'origin', cve_id])


def update_git_repo_info():
    """ updates git remote information. """
    subprocess.check_call(['git', 'remote', 'update'])


def main():
    if len(sys.argv) <= 1:
        sys.exit('Please specify a year.')
    year = int(sys.argv[1])
    update_git_repo_info()
    used_cve_ids = set(get_used_cve_id_from_git_branches())
    year_allocation = os.path.join(
        utils.get_internal_cvelist_location(), str(year))
    files = utils.get_file_listing_for_path(year_allocation, ['*.json'])
    free_cve_ids = list(get_free_cve_ids(used_cve_ids, files))
    if not free_cve_ids:
        sys.exit('No free CVE ids for %s. Request more from mitre.' % (
            year))
    cve_id_to_reserve, cve_id_f_path = free_cve_ids[0]
    print('Reserving', cve_id_to_reserve)
    reserve_cve_id(cve_id_to_reserve, cve_id_f_path)
    print('Creating a git branch for', cve_id_to_reserve)
    reserve_cve_id_in_git(cve_id_to_reserve)
    print('\nPlease modify %s as desired and then commit & '
          'push your changes.' % (cve_id_f_path))


if __name__ == '__main__':
    main()
