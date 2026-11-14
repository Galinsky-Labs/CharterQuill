import { bootQuill } from "@distributed-governance/engine/web/shell.jsx";
import { enginePages } from "@distributed-governance/engine/web/engine-pages.jsx";
import { charterPages } from "./charter-pages.jsx";

bootQuill({ pages: [...enginePages, ...charterPages] });
