import { Routes } from '@angular/router';
import { AmountsComponent, TimeComponent } from './report.components';

export function buildReportRoutes(): Routes {
	const children: Routes = [
		{ path: 'time', component: TimeComponent },
		{ path: 'amounts', component: AmountsComponent }
	];
	return [{ path: '', children }];
}
