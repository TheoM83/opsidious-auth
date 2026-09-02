// Two-pass rendering: the view first, then the layout with the result as its
// body. Every route used to spell this out itself, three times over, which is
// three places for a local like `t` to be forgotten from.

import { join } from 'node:path';

export function renderPage(res, view, locals = {}) {
  const views = res.app.get('views');
  return new Promise((resolve, reject) => {
    res.render(join(views, `${view}.ejs`), locals, (err, body) => {
      if (err) return reject(err);
      res.render(join(views, 'layout.ejs'), { ...locals, body }, (layoutErr, html) => {
        if (layoutErr) return reject(layoutErr);
        res.send(html);
        resolve(html);
      });
    });
  });
}
