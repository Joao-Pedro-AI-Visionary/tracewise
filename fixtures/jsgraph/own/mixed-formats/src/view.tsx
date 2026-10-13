import { Level } from "./util.ts";

export const View = ({ title, level = Level.Low }: { title: string; level?: Level }) => (
  <section data-level={level} onClick={() => fetch(`/api/${title}`)}>
    <h1>{title}</h1>
    <>{[1, 2, 3].map((n) => <i key={n}>{n}</i>)}</>
  </section>
);
