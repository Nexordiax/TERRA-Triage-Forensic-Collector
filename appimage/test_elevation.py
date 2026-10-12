"""Verify privileged relaunch commands without requesting administrator access."""
import unittest
from elevation import relaunch_arguments


class ElevationTests(unittest.TestCase):
    image = '/media/Test USB/TERRA.AppImage'
    launcher = '/tmp/.mount_TERRA/usr/python/bin/python'
    arguments = ['/usr/bin/env','DISPLAY=:0','XAUTHORITY=/home/user/.Xauthority',
                 launcher,'-B','/tmp/.mount_TERRA/usr/share/terra/main.py','--elevated-session']

    def test_mount_relaunch_uses_original_image(self):
        args = relaunch_arguments(self.arguments,self.image,self.launcher)
        self.assertEqual(args[-2:],[self.image,'--elevated-session'])
        self.assertIn('DISPLAY=:0',args)
        self.assertIn('XAUTHORITY=/home/user/.Xauthority',args)
        self.assertNotIn(self.launcher,args)
        self.assertNotIn(self.arguments[-2],args)

    def test_extraction_is_separate_from_user_temp_cache(self):
        args = relaunch_arguments(self.arguments,self.image,self.launcher,extract=True)
        self.assertEqual(args[-3:],[self.image,'--appimage-extract-and-run','--elevated-session'])
        self.assertIn('TMPDIR=/var/tmp',args)

    def test_unrelated_commands_are_unchanged(self):
        for args in ([],['other'],['/usr/bin/env',self.launcher,'-m','analyzers.content_worker']):
            self.assertEqual(relaunch_arguments(args,self.image,self.launcher),args)

    def test_stale_environment_values_are_replaced(self):
        args = self.arguments[:1]+['APPIMAGE=/wrong','TMPDIR=/tmp']+self.arguments[1:]
        result = relaunch_arguments(args,self.image,self.launcher,extract=True)
        self.assertNotIn('APPIMAGE=/wrong',result)
        self.assertNotIn('TMPDIR=/tmp',result)
        self.assertIn('APPIMAGE='+self.image,result)

if __name__ == '__main__': unittest.main()
