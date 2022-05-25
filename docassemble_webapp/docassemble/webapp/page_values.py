import json
import re

from docassemble.base.config import daconfig
from docassemble.webapp.app_object import app
from docassemble.webapp.backend import url_for
from docassemble.webapp.config_server import DEFAULT_LANGUAGE
from docassemble.webapp.config_server import google_config, ga_configured
from docassemble.webapp.setup import da_version
from docassemble.webapp.util import indent_by, test_for_valid_var
import docassemble.base.functions
from docassemble.base.error import DAError
from docassemble.base.logger import logmessage


def standard_scripts(interview_language=DEFAULT_LANGUAGE, external=False):
    if interview_language in ('ar', 'cs', 'et', 'he', 'ka', 'nl', 'ro', 'th', 'zh', 'az', 'da', 'fa', 'hu', 'kr', 'no', 'ru', 'tr', 'bg', 'de', 'fi', 'id', 'kz', 'pl', 'sk', 'uk', 'ca', 'el', 'fr', 'it', 'sl', 'uz', 'cr', 'es', 'gl', 'ja', 'lt', 'pt', 'sv', 'vi'):
        fileinput_locale = '\n    <script src="' + url_for('static', filename='bootstrap-fileinput/js/locales/' + interview_language + '.js', v=da_version, _external=external) + '"></script>'
    else:
        fileinput_locale = ''
    return '\n    <script src="' + url_for('static', filename='app/bundle.js', v=da_version, _external=external) + '"></script>' + fileinput_locale


def additional_scripts(interview_status, yaml_filename, as_javascript=False):
    scripts = ''
    interview_package = re.sub(r'^docassemble\.', '', re.sub(r':.*', '', yaml_filename))
    interview_filename = re.sub(r'\.ya?ml$', '', re.sub(r'.*[:/]', '', yaml_filename), re.IGNORECASE)
    if 'google maps api key' in google_config:
        api_key = google_config.get('google maps api key')
    elif 'api key' in google_config:
        api_key = google_config.get('api key')
    else:
        api_key = None
    if ga_configured and interview_status.question.interview.options.get('analytics on', True):
        ga_id = google_config.get('analytics id')
    else:
        ga_id = None
    output_js = ''
    if api_key is not None:
        region = google_config.get('region', None)
        if region is None:
            region = ''
        else:
            region = '&region=' + region
        scripts += "\n" + '    <script src="https://maps.googleapis.com/maps/api/js?key=' + api_key + region + '&libraries=places"></script>'
        if as_javascript:
            output_js += """\
      var daScript = document.createElement('script');
      daScript.src = "https://maps.googleapis.com/maps/api/js?key=""" + api_key + """&libraries=places";
      document.head.appendChild(daScript);
"""
    if ga_id is not None:
        the_js = """\
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      function daPageview(){
        var idToUse = daQuestionID['id'];
        if (daQuestionID['ga'] != undefined && daQuestionID['ga'] != null){
          idToUse = daQuestionID['ga'];
        }
        if (idToUse != null){
          gtag('config', """ + json.dumps(ga_id) + """, {""" + ("'cookie_flags': 'SameSite=None;Secure', " if app.config['SESSION_COOKIE_SECURE'] else '') + """'page_path': """ + json.dumps(interview_package) + """ + "/" + """ + json.dumps(interview_filename) + """ + "/" + idToUse.replace(/[^A-Za-z0-9]+/g, '_')});
        }
      }
"""
        scripts += """
    <script async src="https://www.googletagmanager.com/gtag/js?id=""" + ga_id + """"></script>
    <script>
""" + the_js + """
    </script>
"""
        if as_javascript:
            output_js += the_js
    if as_javascript:
        return output_js
    return scripts


def additional_css(interview_status, js_only=False):
    if 'segment id' in daconfig and interview_status.question.interview.options.get('analytics on', True):
        segment_id = daconfig['segment id']
    else:
        segment_id = None
    start_output = ''
    the_js = ''
    if segment_id is not None:
        segment_js = """\
      !function(){var analytics=window.analytics=window.analytics||[];if(!analytics.initialize)if(analytics.invoked)window.console&&console.error&&console.error("Segment snippet included twice.");else{analytics.invoked=!0;analytics.methods=["trackSubmit","trackClick","trackLink","trackForm","pageview","identify","reset","group","track","ready","alias","debug","page","once","off","on"];analytics.factory=function(t){return function(){var e=Array.prototype.slice.call(arguments);e.unshift(t);analytics.push(e);return analytics}};for(var t=0;t<analytics.methods.length;t++){var e=analytics.methods[t];analytics[e]=analytics.factory(e)}analytics.load=function(t,e){var n=document.createElement("script");n.type="text/javascript";n.async=!0;n.src="https://cdn.segment.com/analytics.js/v1/"+t+"/analytics.min.js";var a=document.getElementsByTagName("script")[0];a.parentNode.insertBefore(n,a);analytics._loadOptions=e};analytics.SNIPPET_VERSION="4.1.0";
      analytics.load(""" + json.dumps(segment_id) + """);
      analytics.page();
      }}();
      function daSegmentEvent(){
        var idToUse = daQuestionID['id'];
        useArguments = false;
        if (daQuestionID['segment'] && daQuestionID['segment']['id']){
          idToUse = daQuestionID['segment']['id'];
          if (daQuestionID['segment']['arguments']){
            for (var keyToUse in daQuestionID['segment']['arguments']){
              if (daQuestionID['segment']['arguments'].hasOwnProperty(keyToUse)){
                useArguments = true;
                break;
              }
            }
          }
        }
        if (idToUse != null){
          if (useArguments){
            analytics.track(idToUse.replace(/[^A-Za-z0-9]+/g, '_'), daQuestionID['segment']['arguments']);
          }
          else{
            analytics.track(idToUse.replace(/[^A-Za-z0-9]+/g, '_'));
          }
        }
      }
"""
        start_output += """
    <script>
""" + segment_js + """\
    </script>"""
        the_js += segment_js
    if len(interview_status.extra_css) > 0:
        start_output += '\n' + indent_by("".join(interview_status.extra_css).strip(), 4).rstrip()
    if js_only:
        return the_js
    return start_output

def standard_html_start(interview_language=DEFAULT_LANGUAGE, debug=False, bootstrap_theme=None, external=False, page_title=None, social=None, yaml_filename=None):
    if social is None:
        social = {}
    if page_title is None:
        page_title = app.config['BRAND_NAME']
    if bootstrap_theme is None and app.config['BOOTSTRAP_THEME'] is not None:
        bootstrap_theme = app.config['BOOTSTRAP_THEME']
    if bootstrap_theme is None:
        bootstrap_part = '\n    <link href="' + url_for('static', filename='bootstrap/css/bootstrap.min.css', v=da_version, _external=external) + '" rel="stylesheet">'
    else:
        bootstrap_part = '\n    <link href="' + bootstrap_theme + '" rel="stylesheet">'
    output = '<!DOCTYPE html>\n<html lang="' + interview_language + '" itemscope itemtype="http://schema.org/WebPage">\n  <head>\n    <meta charset="utf-8">\n    <meta name="mobile-web-app-capable" content="yes">\n    <meta name="apple-mobile-web-app-capable" content="yes">\n    <meta http-equiv="X-UA-Compatible" content="IE=edge">\n    <meta name="viewport" content="width=device-width, initial-scale=1">\n    ' + ('<link rel="shortcut icon" href="' + url_for('files.favicon', _external=external, **app.config['FAVICON_PARAMS']) + '">\n    ' if app.config['USE_FAVICON'] else '') + ('<link rel="apple-touch-icon" sizes="180x180" href="' + url_for('files.apple_touch_icon', _external=external, **app.config['FAVICON_PARAMS']) + '">\n    ' if app.config['USE_APPLE_TOUCH_ICON'] else '') + ('<link rel="icon" type="image/png" href="' + url_for('files.favicon_md', _external=external, **app.config['FAVICON_PARAMS']) + '" sizes="32x32">\n    ' if app.config['USE_FAVICON_MD'] else '') + ('<link rel="icon" type="image/png" href="' + url_for('files.favicon_sm', _external=external, **app.config['FAVICON_PARAMS']) + '" sizes="16x16">\n    ' if app.config['USE_FAVICON_SM'] else '') + ('<link rel="manifest" href="' + url_for('files.favicon_site_webmanifest', _external=external, **app.config['FAVICON_PARAMS']) + '">\n    ' if app.config['USE_SITE_WEBMANIFEST'] else '') + ('<link rel="mask-icon" href="' + url_for('files.favicon_safari_pinned_tab', _external=external, **app.config['FAVICON_PARAMS']) + '" color="' + app.config['FAVICON_MASK_COLOR'] + '">\n    ' if app.config['USE_SAFARI_PINNED_TAB'] else '') + '<meta name="msapplication-TileColor" content="' + app.config['FAVICON_TILE_COLOR'] + '">\n    <meta name="theme-color" content="' + app.config['FAVICON_THEME_COLOR'] + '">\n    <script defer src="' + url_for('static', filename='fontawesome/js/all.min.js', v=da_version, _external=external) + '"></script>' + bootstrap_part + '\n    <link href="' + url_for('static', filename='app/bundle.css', v=da_version, _external=external) + '" rel="stylesheet">'
    if debug:
        output += '\n    <link href="' + url_for('static', filename='app/pygments.min.css', v=da_version, _external=external) + '" rel="stylesheet">'
    page_title = page_title.replace('\n', ' ').replace('"', '&quot;').strip()
    for key, val in social.items():
        if key not in ('twitter', 'og', 'fb'):
            output += '\n    <meta name="' + key + '" content="' + social[key] + '">'
    if 'description' in social:
        output += '\n    <meta itemprop="description" content="' + social['description'] + '">'
    if 'image' in social:
        output += '\n    <meta itemprop="image" content="' + social['image'] + '">'
    if 'name' in social:
        output += '\n    <meta itemprop="name" content="' + social['name'] + '">'
    else:
        output += '\n    <meta itemprop="name" content="' + page_title + '">'
    if 'twitter' in social:
        if 'card' not in social['twitter']:
            output += '\n    <meta name="twitter:card" content="summary">'
        for key, val in social['twitter'].items():
            output += '\n    <meta name="twitter:' + key + '" content="' + val + '">'
        if 'title' not in social['twitter']:
            output += '\n    <meta name="twitter:title" content="' + page_title + '">'
    if 'fb' in social:
        for key, val in social['fb'].items():
            output += '\n    <meta name="fb:' + key + '" content="' + val + '">'
    if 'og' in social and 'image' in social['og']:
        for key, val in social['og'].items():
            output += '\n    <meta name="og:' + key + '" content="' + val + '">'
        if 'title' not in social['og']:
            output += '\n    <meta name="og:title" content="' + page_title + '">'
        if yaml_filename and 'url' not in social['og']:
            output += '\n    <meta name="og:url" content="' + url_for('index.index', i=yaml_filename, _external=True) + '">'
        if 'site_name' not in social['og']:
            output += '\n    <meta name="og:site_name" content="' + app.config['BRAND_NAME'].replace('\n', ' ').replace('"', '&quot;').strip() + '">'
        if 'locale' not in social['og']:
            output += '\n    <meta name="og:locale" content="' + app.config['OG_LOCALE'] + '">'
        if 'type' not in social['og']:
            output += '\n    <meta name="og:type" content="website">'
    return output


def navigation_bar(nav, interview, wrapper=True, inner_div_class=None, inner_div_extra=None, show_links=None, hide_inactive_subs=True, a_class=None, show_nesting=True, include_arrows=False, always_open=False, return_dict=None):
    if show_links is None:
        show_links = not bool(hasattr(nav, 'disabled') and nav.disabled)
    if inner_div_class is None:
        inner_div_class = 'nav flex-column nav-pills danav danavlinks danav-vertical danavnested'
    if inner_div_extra is None:
        inner_div_extra = ''
    if a_class is None:
        a_class = 'nav-link danavlink'
        muted_class = ' text-muted'
    else:
        muted_class = ''
    the_language = docassemble.base.functions.get_language()
    non_progressive = bool(hasattr(nav, 'progressive') and not nav.progressive)
    auto_open = bool(always_open or (hasattr(nav, 'auto_open') and nav.auto_open))
    if the_language not in nav.sections:
        the_language = DEFAULT_LANGUAGE
    if the_language not in nav.sections:
        the_language = '*'
    if the_language not in nav.sections:
        return ''
    the_sections = nav.sections[the_language]
    if len(the_sections) == 0:
        return ''
    if docassemble.base.functions.this_thread.current_question.section is not None:
        the_section = docassemble.base.functions.this_thread.current_question.section
    else:
        the_section = nav.current
    if the_section is None:
        if isinstance(the_sections[0], dict):
            the_section = list(the_sections[0])[0]
        else:
            the_section = the_sections[0]
    if wrapper:
        output = '<div role="navigation" class="offset-xl-1 col-xl-2 col-lg-3 col-md-3 d-none d-md-block danavdiv">\n  <div class="nav flex-column nav-pills danav danav-vertical danavlinks">\n'
    else:
        output = ''
    section_reached = False
    indexno = 0
    seen = set()
    on_first = True
    for x in the_sections:
        if include_arrows and not on_first:
            output += '<span class="dainlinearrow"><i class="fas fa-chevron-right"></i></span>'
        on_first = False
        indexno += 1
        the_key = None
        subitems = None
        currently_active = False
        if isinstance(x, dict):
            if len(x) == 2 and 'subsections' in x:
                for key, val in x.items():
                    if key == 'subsections':
                        subitems = val
                    else:
                        the_key = key
                        test_for_valid_var(the_key)
                        the_title = val
            elif len(x) == 1:
                the_key = list(x)[0]
                value = x[the_key]
                if isinstance(value, list):
                    subitems = value
                    the_title = the_key
                else:
                    test_for_valid_var(the_key)
                    the_title = value
            else:
                raise DAError("navigation_bar: too many keys in dict.  " + str(the_sections))
        else:
            the_key = None
            the_title = str(x)
        if (the_key is not None and the_section == the_key) or the_section == the_title:
            section_reached = True
            currently_active = True
            active_class = ' active'
            if return_dict is not None:
                return_dict['parent_key'] = the_key
                return_dict['parent_title'] = the_title
                return_dict['key'] = the_key
                return_dict['title'] = the_title
        else:
            active_class = ''
        new_key = the_title if the_key is None else the_key
        seen.add(new_key)
        relevant_past = nav.past.intersection(set(nav.section_ids()))
        seen_more = bool(len(relevant_past.difference(seen)) > 0 or new_key in nav.past or the_title in nav.past)
        if non_progressive:
            seen_more = True
            section_reached = False
        if show_links and (seen_more or currently_active or not section_reached) and the_key is not None and interview is not None and the_key in interview.questions:
            if section_reached and not currently_active and not seen_more:
                output += '<span tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + ' danotavailableyet' + muted_class + '">' + str(the_title) + '</span>'
            else:
                if active_class == '' and not (seen_more and not section_reached):
                    output += '<span tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + ' inactive' + muted_class + '">' + str(the_title) + '</span>'
                else:
                    output += '<a href="#" data-key="' + the_key + '" data-index="' + str(indexno) + '" class="daclickable ' + a_class + active_class + '">' + str(the_title) + '</a>'
        else:
            if section_reached and not currently_active and not seen_more:
                output += '<span tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + ' danotavailableyet' + muted_class + '">' + str(the_title) + '</span>'
            else:
                if active_class == '' and not (seen_more and not section_reached):
                    output += '<span tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + ' inactive' + muted_class + '">' + str(the_title) + '</span>'
                else:
                    output += '<a tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + active_class + '">' + str(the_title) + '</a>'
        suboutput = ''
        if subitems:
            current_is_within = False
            oldindexno = indexno
            for y in subitems:
                if include_arrows:
                    suboutput += '<span class="dainlinearrow"><i class="fas fa-chevron-right"></i></span>'
                indexno += 1
                sub_currently_active = False
                if isinstance(y, dict):
                    if len(y) == 1:
                        sub_key = list(y)[0]
                        test_for_valid_var(sub_key)
                        sub_title = y[sub_key]
                    else:
                        raise DAError("navigation_bar: too many keys in dict.  " + str(the_sections))
                else:
                    sub_key = None
                    sub_title = str(y)
                if (sub_key is not None and the_section == sub_key) or the_section == sub_title:
                    section_reached = True
                    current_is_within = True
                    sub_currently_active = True
                    sub_active_class = ' active'
                    if return_dict is not None:
                        return_dict['key'] = sub_key
                        return_dict['title'] = sub_title
                else:
                    sub_active_class = ''
                new_sub_key = sub_title if sub_key is None else sub_key
                seen.add(new_sub_key)
                relevant_past = nav.past.intersection(set(nav.section_ids()))
                seen_more = bool(len(relevant_past.difference(seen)) > 0 or new_sub_key in nav.past or sub_title in nav.past)
                if non_progressive:
                    seen_more = True
                    section_reached = False
                if show_links and (seen_more or sub_currently_active or not section_reached) and sub_key is not None and interview is not None and sub_key in interview.questions:
                    suboutput += '<a href="#" data-key="' + sub_key + '" data-index="' + str(indexno) + '" class="daclickable ' + a_class + sub_active_class + '">' + str(sub_title) + '</a>'
                else:
                    if section_reached and not sub_currently_active and not seen_more:
                        suboutput += '<span tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + ' danotavailableyet' + muted_class + '">' + str(sub_title) + '</span>'
                    else:
                        suboutput += '<a tabindex="-1" data-index="' + str(indexno) + '" class="' + a_class + sub_active_class + ' inactive">' + str(sub_title) + '</a>'
            if currently_active or current_is_within or hide_inactive_subs is False or show_nesting:
                if currently_active or current_is_within or auto_open:
                    suboutput = '<div class="' + inner_div_class + '"' + inner_div_extra + '>' + suboutput
                else:
                    suboutput = '<div style="display: none;" class="danotshowing ' + inner_div_class + '"' + inner_div_extra + '>' + suboutput
                suboutput += "</div>"
                output += suboutput
            else:
                indexno = oldindexno
    if wrapper:
        output += "\n</div>\n</div>\n"
    if (not non_progressive) and (not section_reached):
        logmessage("Section \"" + str(the_section) + "\" did not exist.")
    return output

def exit_href(status):
    return docassemble.base.functions.url_action('_da_exit')