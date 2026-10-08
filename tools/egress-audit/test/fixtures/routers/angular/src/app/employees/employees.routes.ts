import { Route } from '@angular/router';
import { EditComponent, ProfileComponent } from './employee.components';

export const EMPLOYEE_ROUTES: Route[] = [
	{ path: '', component: ProfileComponent },
	{ path: 'edit', component: EditComponent }
];
