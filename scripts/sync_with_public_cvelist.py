#!/usr/bin/python
import argparse
import datetime
import os
import shutil

import dateutil.parser

from . import utils


def setup_opts():
    parser = argparse.ArgumentParser(
        description='A script that can be used to synchronise an internal '
        'cvelist and the public cvelist.')
    parser.add_argument('-p', '--path-to-cvelist-repository',
                        dest='public_cvelist_path', required=True,
                        help='Path to the public cvelist repository.')
    parser.add_argument(
        '-d', '--direction', dest='direction',
        choices=['to_public', 'from_public'],
        help=('Specify to_public to update the public cvelist '
              'from the internal cvelist. '
              'Specify from_public to update the internal cvelist '
              'from the public cvelist.'),
        required=True,
    )
    return parser


def sync_cve_files(files, copying_to, direction):
    for a_file in sorted(files):
        a_dir = os.path.dirname(a_file).split('cvelist')[-1].lstrip(os.sep)
        dest = os.path.join(copying_to, a_dir)
        base_name = os.path.basename(a_file)
        existing_json_data = utils.get_info_from_cve_json_file(a_file)
        today = datetime.datetime.now()
        state = utils.get_state_from_cve_json(existing_json_data)
        if direction == 'from_public' and state == 'RESERVED':
            possible_existing_location = os.path.join(dest, base_name)
            if os.path.exists(possible_existing_location):
                print('Not copying %s as it already exists at %s' % (
                    a_file, possible_existing_location))
                continue
        if direction == 'to_public':
            if state in {'IN_PROGRESS', 'RESERVED'}:
                print('Not copying %s as it is %s' % (a_file, state))
                continue
            public_date = utils.get_public_date_from_cve_json(
                existing_json_data)
            if public_date is not None:
                public_date_obj = dateutil.parser.parse(public_date)
                if public_date_obj > today:
                    print(('Not copying %s as it is before the '
                           'PUBLIC_DATE %s (now - %s)') %
                          (a_file, public_date, today))
                    continue
        if state not in {'RESERVED', 'PUBLIC'}:
            raise ValueError('%s is not a valid state - %s' % (state, a_file))
        os.makedirs(dest, exist_ok=True)
        dest_file = os.path.join(dest, base_name)
        shutil.copy(a_file, dest_file)


def main():
    args = setup_opts().parse_args()
    internal_cvelist = utils.get_internal_cvelist_location()
    files_to_match = []
    for cve_id in utils.get_our_cna_cve_ids():
        files_to_match.append('%s.json' % cve_id)
    if args.direction == 'to_public':
        copying_to = args.public_cvelist_path
        copying_from = internal_cvelist
    if args.direction == 'from_public':
        copying_to = internal_cvelist
        copying_from = args.public_cvelist_path
    files = set(utils.get_file_listing_for_path(copying_from,
                                                files_to_match))
    sync_cve_files(files, copying_to, args.direction)


if __name__ == '__main__':
    main()
