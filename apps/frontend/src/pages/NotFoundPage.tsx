import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="panel mx-auto mt-10 max-w-md p-8 text-center">
      <p className="text-[15px] font-semibold">Page not found</p>
      <p className="mt-2 text-[13px] text-muted">The link may be outdated, or the resource was removed.</p>
      <Link to="/" className="link mt-4 inline-block text-[13px]">
        Go to overview
      </Link>
    </div>
  );
}
