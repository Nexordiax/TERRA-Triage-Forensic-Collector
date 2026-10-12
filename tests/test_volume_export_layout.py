"""Logical-volume mapping and ZIP timestamp interoperability contracts."""
import io
import struct
import unittest
import zipfile

from controllers.export_controller import ArchivePaths
from reporting.zip_metadata import evidence_info, FILETIME_EPOCH


def fields(extra):
    result = {}
    while extra:
        kind, size = struct.unpack_from('<HH', extra)
        result[kind] = extra[4:4 + size]
        extra = extra[4 + size:]
    return result


class VolumeExportLayoutTests(unittest.TestCase):
    def mounts(self):
        return [dict(device=10, mount_point='/', filesystem_root='/', filesystem_type='ext4', device_source='/dev/sda1'),
                dict(device=20, mount_point='/media/USB', filesystem_root='/', filesystem_type='exfat', device_source='/dev/sdb1')]

    def test_folders_on_same_volume_keep_full_paths_and_share_root(self):
        paths = ArchivePaths({'paths': ['/home/alice', '/etc']}, volumes=self.mounts())
        self.assertEqual(paths.path_for('/home/alice/.mozilla/places.sqlite', 10), 'evidence/volume-001/home/alice/.mozilla/places.sqlite')
        self.assertEqual(paths.path_for('/etc/passwd', 10), 'evidence/volume-001/etc/passwd')
        self.assertEqual(paths.evidence_roots[0]['selected_source_roots'], ['/home/alice', '/etc'])
        self.assertEqual(paths.evidence_roots[0]['filesystem_type'], 'ext4')

    def test_usb_is_separate_and_uses_filesystem_paths(self):
        paths = ArchivePaths({'paths': ['/home/alice', '/media/USB/photos']}, volumes=self.mounts())
        paths.path_for('/home/alice/picture.jpg', 10)
        self.assertEqual(paths.path_for('/media/USB/photos/picture.jpg', 20), 'evidence/volume-002/photos/picture.jpg')
        self.assertEqual(paths.evidence_roots[1]['mount_point'], '/media/USB')

    def test_unknown_original_device_never_uses_replacement_mount(self):
        paths = ArchivePaths({'paths': ['/media/USB']}, volumes=self.mounts())
        self.assertEqual(paths.path_for('/media/USB/photo.jpg', 99), 'evidence/volume-001/media/USB/photo.jpg')
        self.assertIsNone(paths.evidence_roots[0]['mount_point'])

    def test_bind_root_and_unicode_and_database_companions(self):
        mounts = [dict(device=10, mount_point='/offline', filesystem_root='/home', filesystem_type='ext4')]
        paths = ArchivePaths({'paths': ['/offline']}, volumes=mounts)
        self.assertEqual(paths.path_for('/offline/عربي/été.jpg', 10), 'evidence/volume-001/home/عربي/été.jpg')
        first = paths.path_for('/offline/places.sqlite-wal', 10)
        database = paths.path_for('/offline/places.sqlite', 10)
        self.assertEqual(first, database + '-wal')
        second = paths.path_for('/offline/PLACES.sqlite', 10)
        self.assertNotEqual(second.casefold(), database.casefold())
        self.assertEqual(paths.path_for('/offline/PLACES.sqlite-shm', 10), second + '-shm')

    def test_local_and_central_timestamps_preserve_utc_precision(self):
        modified = 1791720001123456789
        accessed = modified - 60000000000
        record = dict(mtime_ns=modified, atime_ns=accessed, ctime_ns=modified + 1000)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr(evidence_info('evidence/volume-001/été.jpg', record), b'original')
        with zipfile.ZipFile(io.BytesIO(output.getvalue())) as archive:
            info = archive.infolist()[0]
            self.assertEqual(archive.read(info), b'original')
            self.assertTrue(info.flag_bits & 0x800)
            extra = fields(info.extra)
            self.assertEqual(struct.unpack('<Bi', extra[0x5455]), (1, modified // 1000000000))
            reserved, tag, length, mt, at, birth = struct.unpack('<IHHQQQ', extra[0x000A])
            self.assertEqual((reserved, tag, length), (0, 1, 24))
            self.assertEqual(mt, modified // 100 + FILETIME_EPOCH)
            self.assertEqual(at, accessed // 100 + FILETIME_EPOCH)
            self.assertEqual(birth, 0)  # POSIX ctime must never become birth time.
            raw = output.getvalue()
            filename_size, extra_size = struct.unpack_from('<HH', raw, 26)
            local_extra = raw[30 + filename_size:30 + filename_size + extra_size]
            self.assertEqual(fields(local_extra), extra)

    def test_out_of_dos_range_and_missing_timestamps(self):
        record = dict(mtime_ns=-1000000000)
        info = evidence_info('old.txt', record)
        self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
        self.assertEqual(struct.unpack('<Bi', fields(info.extra)[0x5455]), (1, -1))
        self.assertEqual(evidence_info('unknown.txt', {}).extra, b'')
