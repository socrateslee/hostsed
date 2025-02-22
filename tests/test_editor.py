import unittest
from hostsed import editor


class TestHostEditor(unittest.TestCase):

    def test_add(self):
        content = "127.0.0.1\tlocalhost"
        he = editor.HostEditor(content)
        he.add("192.168.1.1", "test.com")
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost\n192.168.1.1\ttest.com")

        he.add("192.168.1.1", "test2.com")
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost\n192.168.1.1\ttest.com\ttest2.com")

    def test_add_invalid_ip(self):
        content = ""
        he = editor.HostEditor(content)
        with self.assertRaises(Exception):
            he.add("invalid_ip", "test.com")

    def test_drop(self):
        content = "127.0.0.1\tlocalhost\n192.168.1.1\ttest.com\n192.168.1.1\ttest2.com"
        he = editor.HostEditor(content)
        he.drop("192.168.1.1")
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost")

        content = "127.0.0.1\tlocalhost\n192.168.1.1\ttest.com\n192.168.1.2\ttest.com"
        he = editor.HostEditor(content)
        he.drop("test.com")
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost")

    def test_delete(self):
        content = "127.0.0.1\tlocalhost\n192.168.1.1\ttest.com\ttest2.com"
        he = editor.HostEditor(content)
        he.delete("192.168.1.1", "test.com")
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost\n192.168.1.1\ttest2.com")

        he.delete("192.168.1.1", "test2.com")
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost")

    def test_delete_invalid_ip(self):
        content = ""
        he = editor.HostEditor(content)
        with self.assertRaises(Exception):
            he.delete("invalid_ip", "test.com")

    def test_parse(self):
        content = "127.0.0.1\tlocalhost\n# comment\n192.168.1.1\ttest.com"
        he = editor.HostEditor(content)
        self.assertEqual(len(he.entries), 3)
        self.assertEqual(he.entries[0][1], ["127.0.0.1", "localhost"])
        self.assertEqual(he.entries[1][1], None)
        self.assertEqual(he.entries[2][1], ["192.168.1.1", "test.com"])

    def test_render(self):
        content = "127.0.0.1\tlocalhost\n# comment\n192.168.1.1\ttest.com"
        he = editor.HostEditor(content)
        self.assertEqual(he.render(), "127.0.0.1\tlocalhost\n# comment\n192.168.1.1\ttest.com")

    def test_is_valid_ip_address(self):
        self.assertTrue(editor.is_valid_ip_address("127.0.0.1"))
        self.assertTrue(editor.is_valid_ip_address("::1"))
        self.assertFalse(editor.is_valid_ip_address("invalid"))

    def test_parse_line(self):
      self.assertEqual(editor.parse_line("127.0.0.1 localhost # comment"), ('127.0.0.1 localhost # comment', ['127.0.0.1', 'localhost'], '# comment'))
      self.assertEqual(editor.parse_line("# comment"), ('# comment', None, '# comment'))
      self.assertEqual(editor.parse_line(""), ('', None, ''))

if __name__ == '__main__':
    unittest.main()