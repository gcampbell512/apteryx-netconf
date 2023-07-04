from conftest import _get_test_with_filter


# GET XPATH


def test_get_xpath_node():
    xpath = '/test/settings/debug'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <settings>
            <debug>enable</debug>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}debug').text == 'enable'


# No default or prefixed namespace - we use the internal default namespace
def test_get_xpath_node_ns_none():
    xpath = '/test/settings/priority'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <settings>
            <priority>1</priority>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}priority').text == '1'


def test_get_xpath_node_ns_aug_none():
    xpath = '/test/settings/volume'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <settings>
            <volume>1</volume>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}volume').text == '1'


def test_get_xpath_node_ns_default():
    xpath = '/test:test/settings/priority'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <settings>
            <priority>1</priority>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}priority').text == '1'


def test_get_xpath_node_ns_aug_default():
    xpath = '/test:test/settings/volume'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <settings>
            <volume>1</volume>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}volume').text == '1'


# Prefixed namespace is not the internal default namespace
def test_get_xpath_node_ns_other():
    xpath = '/t2:test/t2:settings/t2:priority'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing-2">
        <settings>
            <priority>2</priority>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}priority').text == '2'


def test_get_xpath_node_ns_aug_other():
    xpath = '/t2:test/t2:settings/aug2:speed'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing-2">
        <settings>
            <speed xmlns="http://test.com/ns/yang/testing2-augmented">2</speed>
        </settings>
    </test>
</nc:data>
    """
    xml = _get_test_with_filter(xpath, expected, f_type='xpath')
    assert xml.find('./{*}test/{*}settings/{*}speed').text == '2'


def test_get_xpath_trunk():
    xpath = '/test/settings'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <settings>
            <debug>enable</debug>
            <enable>true</enable>
            <priority>1</priority>
            <volume>1</volume>
        </settings>
    </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_list_trunk():
    xpath = '/test/animals'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test xmlns="http://test.com/ns/yang/testing">
    <animals>
      <animal>
        <name>cat</name>
        <type>big</type>
      </animal>
      <animal>
        <name>dog</name>
        <colour>brown</colour>
      </animal>
      <animal>
        <name>hamster</name>
        <type>little</type>
        <food>
          <name>banana</name>
          <type>fruit</type>
        </food>
        <food>
          <name>nuts</name>
          <type>kibble</type>
        </food>
      </animal>
      <animal>
        <name>mouse</name>
        <type>little</type>
        <colour>grey</colour>
      </animal>
      <animal>
        <name>parrot</name>
        <type>big</type>
        <colour>blue</colour>
      </animal>
    </animals>
  </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_list_select_one_trunk():
    xpath = "/test:test/animals/animal[name='cat']"
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <animals>
            <animal>
                <name>cat</name>
                <type>big</type>
            </animal>
        </animals>
    </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_list_select_one_parameter():
    xpath = "/test:test/animals/animal[name='cat']/type"
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <animals>
            <animal>
                <type>big</type>
            </animal>
        </animals>
    </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_query_multi():
    xpath = ("/test:test/animals/animal[name='cat']/type | /test:test/animals/animal[name='dog']/colour")
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test xmlns="http://test.com/ns/yang/testing">
        <animals>
            <animal>
                <type>big</type>
            </animal>
        </animals>
    </test>
    <test xmlns="http://test.com/ns/yang/testing">
        <animals>
            <animal>
                <colour>brown</colour>
            </animal>
        </animals>
    </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_multi_xpath_select_multi():
    xpath = ("/test:test/animals/animal[name='cat']/type | /exam:interfaces/interface[name='eth2']/mtu")
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test xmlns="http://test.com/ns/yang/testing">
    <animals>
      <animal>
        <type>big</type>
      </animal>
    </animals>
  </test>
  <interfaces xmlns="http://example.com/ns/interfaces">
    <interface>
      <mtu>9000</mtu>
    </interface>
  </interfaces>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_with_slash_slash():
    xpath = '//animal'
    nspace = 'xmlns:test="http://test.com/ns/yang/testing"'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test xmlns="http://test.com/ns/yang/testing">
    <animals>
      <animal>
        <name>cat</name>
        <type>big</type>
      </animal>
      <animal>
        <name>dog</name>
        <colour>brown</colour>
      </animal>
      <animal>
        <name>hamster</name>
        <type>little</type>
        <food>
          <name>banana</name>
          <type>fruit</type>
        </food>
        <food>
          <name>nuts</name>
          <type>kibble</type>
        </food>
      </animal>
      <animal>
        <name>mouse</name>
        <type>little</type>
        <colour>grey</colour>
      </animal>
      <animal>
        <name>parrot</name>
        <type>big</type>
        <colour>blue</colour>
      </animal>
    </animals>
  </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, nspace, f_type='xpath')


def test_get_xpath_with_missing_path_star_path():
    xpath = '/exam:interfaces/*/name'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces xmlns="http://example.com/ns/interfaces">
    <interface>
      <name>eth0</name>
    </interface>
    <interface>
      <name>eth1</name>
    </interface>
    <interface>
      <name>eth2</name>
    </interface>
    <interface>
      <name>eth3</name>
    </interface>
  </interfaces>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_with_path_star_path():
    xpath = '/exam:interfaces/interface/*/name'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces xmlns="http://example.com/ns/interfaces">
    <interface>
      <name>eth0</name>
    </interface>
    <interface>
      <name>eth1</name>
    </interface>
    <interface>
      <name>eth2</name>
    </interface>
    <interface>
      <name>eth3</name>
    </interface>
  </interfaces>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_with_path_star():
    xpath = '/exam:interfaces/interface/*'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces xmlns="http://example.com/ns/interfaces">
    <interface>
      <name>eth0</name>
      <mtu>8192</mtu>
      <status>up</status>
    </interface>
    <interface>
      <name>eth1</name>
      <status>up</status>
    </interface>
    <interface>
      <name>eth2</name>
      <mtu>9000</mtu>
      <status>not feeling so good</status>
    </interface>
    <interface>
      <name>eth3</name>
      <mtu>1500</mtu>
      <status>waking up</status>
    </interface>
  </interfaces>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_with_name_value():
    xpath = '/test:test//*[name="dog"]'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test xmlns="http://test.com/ns/yang/testing">
    <animals>
      <animal>
        <name>dog</name>
        <colour>brown</colour>
      </animal>
    </animals>
  </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_with_name_first():
    xpath = '/test:test//animal[1]'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test xmlns="http://test.com/ns/yang/testing">
    <animals>
      <animal>
        <name>cat</name>
        <type>big</type>
      </animal>
    </animals>
  </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')


def test_get_xpath_with_name_last():
    xpath = '/test:test//animal[last()]'
    expected = """
<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test xmlns="http://test.com/ns/yang/testing">
    <animals>
      <animal>
        <name>parrot</name>
        <type>big</type>
        <colour>blue</colour>
      </animal>
    </animals>
  </test>
</nc:data>
    """
    _get_test_with_filter(xpath, expected, f_type='xpath')
