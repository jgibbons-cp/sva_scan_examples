import xml.sax


class GetAlasLinks(xml.sax.ContentHandler):
    def __init__(self):
        xml.sax.ContentHandler.__init__(self)
        self.match = False
        self.counter = 0
        self.link = ""
        self.cve_id = ""

    def startElement(self, name, attrs):
        pass

    def endElement(self, name):
        pass

    # get the links from the XML
    def characters(self, content):
        FIRST_PASS = 1
        SECOND_PASS = 2

        if self.cve_id in content:
            self.match = True

        if self.match is True:
            if "https://alas.aws.amazon.com/ALAS-" in content:
                self.counter = self.counter + FIRST_PASS

        if "https://alas.aws.amazon.com/ALAS-" in content and \
                self.counter == SECOND_PASS:
            self.link = "%s %s" % (self.link, content)
            self.counter = 0
            self.match = False

    def run(self, source_file_name, cve_id):
        get_alas_links = GetAlasLinks()
        get_alas_links.cve_id = cve_id
        source = open(source_file_name)
        xml.sax.parse(source, get_alas_links)

        return get_alas_links.link
