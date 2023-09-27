rule IgnoreFileHeader {
    strings:
        $string_to_match = /.{2}MZ/  // Ignore the first 2 characters and match any string
    condition:
        $string_to_match
}
