import collections
import json
import fnmatch
import os


def get_file_listing_for_path(path, fnmatches, exact=False):
    """ returns a generator expression for getting the file listing
        of files matching any of the given fnmatches under the supplied
        path, if exact is True then only exact filename matches will be
        accepted.
    """
    for root, dirs, files in os.walk(path):
        for file_ in sorted(files):
            matched = False
            if exact:
                if file_ in fnmatches:
                    matched = True
            else:
                for fnm in fnmatches:
                    if fnmatch.fnmatch(file_, fnm):
                        matched = True
                        break
            if matched:
                yield os.path.join(root, file_)


def get_state_from_cve_json(json_data):
    """ returns the state of the cve id from the given json. """
    return json_data['CVE_data_meta']['STATE']


def get_public_date_from_cve_json(json_data):
    """ returns the date public value from the given json or None
        if it has not been provided.
    """
    return json_data['CVE_data_meta'].get('DATE_PUBLIC', None)


def get_cve_id_from_cve_json(json_data):
    """ returns the cve id value from the given json or None
        if it has not been provided.
    """
    return json_data['CVE_data_meta'].get('ID', None)


def get_info_from_cve_json_file(file_path):
    """ returns cve information from the given cve json file path. """
    with open(file_path, 'r') as f:
        return json.load(f, object_pairs_hook=collections.OrderedDict)


def get_our_cna_cve_ids():
    """ yields our CNA cve ids. """
    range_file_loc = os.path.join(get_internal_cvelist_location(),
                                  'cve_id_ranges.json')
    with open(range_file_loc, 'r') as f:
        data = json.load(f, object_pairs_hook=collections.OrderedDict)
        for rang in data.get('ranges', []):
            start = rang['start']
            end = rang['end']
            start_num = int(start.split('-')[-1])
            end_num = int(end.split('-')[-1])
            start_without_num = start.strip(str(start_num))
            for num in range(start_num, end_num + 1):
                yield '%s%s' % (start_without_num, num)


def get_internal_cvelist_location():
    """ returns the location of the internal cvelist repository. """
    return os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '../'))
