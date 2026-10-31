export default function Page({ post, data }) {
  return (<>
    <div dangerouslySetInnerHTML={{ __html: post.html }} />                    {/* EXPECT xss-dangerously-set-inner-html */}
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} /> {/* EXPECT xss-json-in-script */}
    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.html) }} />  {/* safe: no finding */}
  </>);
}
export function show(el, html) { el.innerHTML = html; }                        // EXPECT xss-inner-html
export function go() { window.location.href = new URLSearchParams(location.search).get('next'); } // EXPECT open-redirect
